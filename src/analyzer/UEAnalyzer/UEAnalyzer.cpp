#include "UEAnalyzer.h"

#include <algorithm>
#include <cstring>
#include <exception>
#include <thread>

#include "../Architecture/IArchDecoder.h"

#include "Analysis/AnchoredResolution.h"
#include "Analysis/CallGraph.h"
#include "Analysis/EhFrameIndex.h"
#include "Analysis/GlobalAccessHarvester.h"
#include "Analysis/LiteralScanner.h"
#include "Analysis/StringAnchors.h"
#include "Analysis/StructureVerifier.h"
#include "Analysis/TCharDetect.h"
#include "Strategies/IStrategy.h"

namespace nextdumper::analyzer
{
	namespace
	{

		/**
		 * @brief Applies the caller's veto.
		 *
		 * Deliberately last, after every built-in check, so the veto can only remove
		 * candidates and never introduce one.
		 */
		void ApplyValidator(std::vector<Candidate> &Candidates, const CandidateValidator &Validator)
		{
			if (!Validator)
				return;
			Candidates.erase(std::remove_if(Candidates.begin(), Candidates.end(), [&](const Candidate &C)
											{ return !Validator(C.Address); }),
							 Candidates.end());
		}

	} // namespace

	/**
	 * @brief The analysis shared by every strategy and both lookups.
	 *
	 * Held behind a shared_ptr so the analyzer stays movable while the heavy
	 * analysis headers stay out of UEAnalyzer.h.
	 */
	struct UEAnalyzer::Analysis
	{
		GlobalAccessHarvester Harvester;

		/**
		 * @brief One strategy and the anchor sites located for it.
		 *
		 * Held per strategy rather than per target kind: the strategy is the
		 * target, so this list *is* the set of things the analyzer can find.
		 */
		struct TargetAnalysis
		{
			StrategyPtr Strategy;
			StringAnchors Anchors;
			/// Ascending, so scoring can binary-search it without sorting per candidate.
			std::vector<uint64_t> AnchorSites;
			/// The same sites, kept per anchor so their weights survive.
			std::vector<StringAnchors::WeightedSites> AnchorSitesByAnchor;
		};
		std::vector<TargetAnalysis> Targets;

		CallGraph Calls;
		AnchoredResolution::AnchorSites ResolutionSites;

		/// Borrowed from the caller, who must keep it alive for the analysis.
		const IArchDecoder *Arch = nullptr;

		/// Fetched once. Everything downstream borrows this rather than calling
		/// GetUnrealModule(), which returns by value.
		ModuleInfo Module;

		/// Decoded once from the module's unwind table; empty when the table is
		/// absent, in which case function bounds fall back to the instruction scan.
		EhFrameIndex EhFrame;

		/// Measured once in Analyze(): the scans behind it are not free, and nothing
		/// about the answer changes between queries.
		ETCharKind TChar = ETCharKind::Unknown;
		size_t TCharUtf16Hits = 0;
		size_t TCharUtf32Hits = 0;

		std::unordered_map<uint64_t, uint32_t> AccessRank;
		uint32_t RankedCount = 0;

		/**
		 * @brief Builds the scoring context for one target.
		 *
		 * Shared by the query path and the diagnostics so a candidate is scored the
		 * same way whether it is being ranked or being explained; a context assembled
		 * twice is a context that drifts.
		 */
		AnalysisContext MakeContext(const TargetAnalysis &Target, IMemory *Mem, const ScoringWeights &Weights) const
		{
			AnalysisContext Ctx;
			Ctx.Memory = Mem;
			Ctx.Module = &Module;
			Ctx.Harvester = &Harvester;
			Ctx.AccessRank = &AccessRank;
			Ctx.RankedCount = RankedCount;
			Ctx.Weights = Weights;
			Ctx.Anchors = &Target.Anchors;
			Ctx.AnchorSites = &Target.AnchorSites;
			Ctx.AnchorSitesByAnchor = &Target.AnchorSitesByAnchor;
			return Ctx;
		}

		/**
		 * @brief Ranks writable, non-executable globals by access count.
		 *
		 * Restricting the ranking to plausible locations is what keeps code and
		 * read-only data from pushing real globals down the list.
		 */
		void BuildRanking()
		{
			std::vector<std::pair<uint64_t, uint32_t>> Ranked;
			Ranked.reserve(Harvester.GetAccesses().size());
			for (const auto &[Address, Info] : Harvester.GetAccesses())
			{
				const MemRegionInfo *Seg = Module.FindAddressRegion(Address);
				if (!Seg || !Seg->IsWriteable() || Seg->IsExecutable())
					continue;
				Ranked.emplace_back(Address, Info.Count);
			}
			std::sort(Ranked.begin(), Ranked.end(), [](const auto &A, const auto &B)
					  {
				if (A.second != B.second)
					return A.second > B.second;
				return A.first < B.first; });

			AccessRank.reserve(Ranked.size());
			for (size_t i = 0; i < Ranked.size(); ++i)
			{
				AccessRank.emplace(Ranked[i].first, static_cast<uint32_t>(i) + 1u);
			}
			RankedCount = static_cast<uint32_t>(Ranked.size());
		}
	};

	bool UEAnalyzer::IsValid() const
	{
		return State_ != nullptr;
	}

	UEAnalyzer UEAnalyzer::Analyze(IMemory *Memory, const IArchDecoder *Arch, AnalyzerOptions Options, HarvestOptions Harvest)
	{
		UEAnalyzer Out;
		Out.Options_ = std::move(Options);
		Out.Memory_ = Memory;

		if (!Memory)
		{
			Out.Error_ = "no memory backend";
			return Out;
		}
		if (!Memory->IsMemoryAccessOk())
		{
			Out.Error_ = "memory backend is not ready";
			return Out;
		}
		if (!Arch)
		{
			Out.Error_ = "no instruction decoder";
			return Out;
		}

		auto State = std::make_shared<Analysis>();
		State->Module = Memory->GetUnrealModule();
		State->EhFrame = EhFrameIndex::Build(*Memory, State->Module);
		State->Arch = Arch;

		// Each strategy brings its own proximity anchors, so locating them needs no
		// knowledge here of what any of them is looking for. Built before either
		// phase runs, because the literal scan below fills them.
		//
		// Only requested strategies contribute needles to the shared literal scans.
		{
			std::vector<StrategyPtr> Available = Targets::CreateAll();

			// Options was moved into Out; use the retained target selection.
			for (StrategyPtr &S : Available)
			{
				if (!Out.Options_.IsTargetWanted(S->Name()))
					continue;
				State->Targets.emplace_back().Strategy = std::move(S);
			}
		}

		// One decode pass feeds everything downstream, including the call graph,
		// rather than sweeping the same bytes a second time for it.
		const auto Harvest_ = [&]
		{ return State->Harvester.Run(Memory, Arch, Harvest, &State->Calls); };

		AnchoredResolution::AnchorSites ResolutionLiterals;
		LiteralScanBatch::Statistics LiteralStats;
		// Finding the anchor strings needs no harvest result, only the bytes, so it
		// is the one phase that can run beside the decode. It writes each target's
		// own StringAnchors and the TCHAR counters, all of which the harvest never
		// touches, and both phases only read from Memory and Module.
		const auto ScanLiterals = [&]
		{
			LiteralScanBatch Batch;
			std::vector<StringAnchors *> Outputs;
			std::vector<std::span<const AnchorString>> Groups;
			for (Analysis::TargetAnalysis &T : State->Targets)
			{
				Outputs.push_back(&T.Anchors);
				Groups.push_back(T.Strategy->ProximityAnchors());
			}
			StringAnchors::RunBatch(Memory, State->Module, Outputs, Groups, &Batch);
			QueueTCharDetection(Batch, State->TChar, State->TCharUtf16Hits, State->TCharUtf32Hits);
			std::vector<const Anchor *> ResolutionAnchors;
			for (const auto &Target : State->Targets)
				for (const Anchor &A : Target.Strategy->ResolutionAnchors())
					ResolutionAnchors.push_back(&A);
			AnchoredResolution::QueueAnchorLiterals(Batch, ResolutionAnchors, ResolutionLiterals);
			Batch.Run(Memory, State->Module);
			LiteralStats = Batch.Stats();
		};

		bool bHarvested = false;
		if (Out.Options_.Progress)
			Out.Options_.Progress("analyzer: instruction harvest started");
		Harvest.Progress = Out.Options_.Progress;
		// Out.Options_ for the same reason as the target filter above. ThreadMode is
		// a scalar and so survives the move intact, but reading a moved-from object
		// at all is what let the Targets bug sit here unnoticed.
		if (Out.Options_.ThreadMode == EThreadMode::Two)
		{
			if (Out.Options_.Progress)
				Out.Options_.Progress("analyzer: literal scan started");
			// The scan goes to the second thread and the harvest stays here, so a
			// failure to spawn is the only thing that could differ - and that throws
			// rather than silently running half the work.
			//
			// Both halves are written so that a throw cannot reach a thread
			// boundary. An exception escaping the worker would call std::terminate
			// outright, and one escaping the harvest would destroy a still-joinable
			// thread, which terminates just the same. Since this code can be hosted
			// inside another process, terminating takes that process down with it -
			// so the worker captures instead of propagating, and the join is owned
			// by a scope guard rather than by a statement that unwinding can skip.
			std::exception_ptr ScanError;
			{
				std::thread Scanner([&]
									{
					try
					{
						ScanLiterals();
					}
					catch (...)
					{
						ScanError = std::current_exception();
					} });

				// std::jthread would join automatically here, but its stdlib support is
				// still missing or partial on some shipped toolchains (notably Apple's
				// libc++); a plain std::thread plus an explicit scope guard gets the same
				// join-before-unwind-escapes guarantee without depending on it.
				struct FJoinOnExit
				{
					std::thread &T;
					~FJoinOnExit()
					{
						if (T.joinable())
							T.join();
					}
				} JoinScanner{Scanner};

				bHarvested = Harvest_();
			}

			// Rethrown only once the worker has been joined, so the captured
			// exception reaches the caller exactly as an unthreaded run would raise
			// it. A harvest failure unwinds first and wins, which matches the
			// single-threaded order.
			if (ScanError)
				std::rethrow_exception(ScanError);
			if (Out.Options_.PhaseCompleted)
				Out.Options_.PhaseCompleted("instruction-and-literal-scan");
		}
		else
		{
			bHarvested = Harvest_();
			if (Out.Options_.PhaseCompleted)
				Out.Options_.PhaseCompleted("instruction-harvest");
			if (Out.Options_.Progress)
				Out.Options_.Progress("analyzer: instruction harvest complete; literal scan started");
			ScanLiterals();
			if (Out.Options_.PhaseCompleted)
				Out.Options_.PhaseCompleted("shared-literal-scan");
		}

		if (!bHarvested)
		{
			Out.Error_ = "harvest failed";
			return Out;
		}

		if (Out.Options_.Progress)
			Out.Options_.Progress("analyzer_literal_scan registered_needles=" + std::to_string(LiteralStats.RegisteredNeedles) +
								  " unique_needles=" + std::to_string(LiteralStats.UniqueNeedles) + " comparisons=" + std::to_string(LiteralStats.Comparisons) +
								  " read_operations=" + std::to_string(LiteralStats.ReadOperations) + " read_bytes=" + std::to_string(LiteralStats.ReadBytes));

		// Needs both phases: the sites come from the harvester, the strings from the
		// scan, so this is the join point rather than part of either.
		for (Analysis::TargetAnalysis &T : State->Targets)
		{
			const std::unordered_set<uint64_t> Sites = T.Anchors.CollectAnchorSites(State->Harvester);
			T.AnchorSites.assign(Sites.begin(), Sites.end());
			std::sort(T.AnchorSites.begin(), T.AnchorSites.end());
			T.AnchorSitesByAnchor = T.Anchors.CollectAnchorSitesByAnchor(State->Harvester);
		}

		State->BuildRanking();
		if (Out.Options_.PhaseCompleted)
			Out.Options_.PhaseCompleted("global-ranking");
		if (Out.Options_.Progress)
			Out.Options_.Progress("analyzer: global ranking complete; mapping shared resolution literals to code sites");
		State->ResolutionSites = AnchoredResolution::MapAnchorSites(ResolutionLiterals, State->Harvester);
		if (Out.Options_.PhaseCompleted)
			Out.Options_.PhaseCompleted("resolution-anchor-mapping");

		if (Out.Options_.Progress)
			Out.Options_.Progress("analyzer: resolution anchor mapping complete");

		Out.State_ = std::move(State);
		return Out;
	}

	namespace
	{
		/// The registered target answering to TargetName, or null when none does.
		const UEAnalyzer::Analysis::TargetAnalysis *FindTarget(const UEAnalyzer::Analysis &State, const char *TargetName)
		{
			if (!TargetName)
				return nullptr;
			for (const auto &Entry : State.Targets)
			{
				if (std::strcmp(Entry.Strategy->Name(), TargetName) == 0)
				{
					return &Entry;
				}
			}
			return nullptr;
		}
	} // namespace

	TargetAssessment UEAnalyzer::AssessAddress(const char *TargetName, uint64_t Address) const
	{
		TargetAssessment Out;
		Out.Target = TargetName ? TargetName : "";

		if (!State_)
		{
			Out.Reason = "analysis unavailable";
			return Out;
		}

		const Analysis::TargetAnalysis *Found = FindTarget(*State_, TargetName);
		if (!Found)
		{
			Out.Reason = "no strategy answers to this target";
			return Out;
		}
		Out.Target = Found->Strategy->Name();

		// Ordered from the earliest thing that can go wrong to the latest, so Reason
		// names the first gate that actually stopped it.
		const MemRegionInfo *Seg = State_->Module.FindAddressRegion(static_cast<uintptr_t>(Address));
		if (!Seg)
		{
			Out.Reason = "not inside the module";
			return Out;
		}
		if (!Seg->IsWriteable() || Seg->IsExecutable())
		{
			Out.Reason = EVerdictToString(EVerdict::NotWritableData);
			return Out;
		}

		const AccessInfo *Info = State_->Harvester.Find(Address);
		if (!Info)
		{
			Out.Reason = EVerdictToString(EVerdict::Unreferenced);
			return Out;
		}

		const StructureVerifier Verifier(State_->Module, State_->Harvester);
		Out.Evidence = Found->Strategy->Verify(Verifier, Address);
		if (!Out.Evidence.Passed)
		{
			Out.Reason = "verification rejected it: " + Out.Evidence.Why;
			return Out;
		}
		Out.Layout = MakeLayoutDescription(Out.Evidence, Address);

		// Verified. Where it stands is read off the same query path a caller would
		// use, so Rank/CandidateCount/bAnswer always agree with Find()'s own answer.
		const LocateResult R = Run(Out.Target, {});
		Out.CandidateCount = R.Candidates.size();
		for (size_t i = 0; i < R.Candidates.size(); ++i)
		{
			if (R.Candidates[i].Address == Address)
			{
				Out.Rank = i + 1;
				break;
			}
		}
		Out.bAnswer = R.bVerified && Out.Rank == 1;

		char Buf[192];
		if (Out.Rank)
		{
			std::snprintf(Buf, sizeof(Buf), "verified, rank %zu of %zu%s", Out.Rank, Out.CandidateCount, Out.bAnswer ? " - returned as the answer" : "");
			Out.Reason = Buf;
			return Out;
		}

		// Verified but not in the returned list: that hides two failures that need
		// opposite fixes - a filter dropped the address, or it scored and ranked too
		// low. Re-run the scorer untrimmed to say which, and where.
		AnalysisContext Ctx = State_->MakeContext(*Found, Memory_, Options_.Weights);
		Ctx.MaxScored = 0;
		const std::vector<Candidate> Scored = Scoring::FuseCandidates(Found->Strategy->Score(Ctx), Options_.Weights);

		size_t FullRank = 0;
		for (size_t i = 0; i < Scored.size(); ++i)
		{
			if (Scored[i].Address == Address)
			{
				FullRank = i + 1;
				break;
			}
		}

		if (FullRank)
			std::snprintf(Buf, sizeof(Buf), "verified, scored rank %zu of %zu - the strategy keeps %zu (%u accesses, %u pointer-width)", FullRank, Scored.size(), kMaxScoredCandidates, Info->Count, Info->WideAccesses);
		else
			std::snprintf(Buf, sizeof(Buf), "verified, but a scoring filter rejected it (%u accesses, %u pointer-width)", Info->Count, Info->WideAccesses);
		Out.Reason = Buf;
		return Out;
	}

	AddressExplanation UEAnalyzer::Explain(uint64_t Address) const
	{
		AddressExplanation Out;
		if (!State_)
			return Out;

		Out.Address = Address;

		if (const MemRegionInfo *Seg = State_->Module.FindAddressRegion(static_cast<uintptr_t>(Address)))
		{
			Out.bInModule = true;
			Out.Segment = Seg->GetPathName();
			Out.bWritable = Seg->IsWriteable();
			Out.bExecutable = Seg->IsExecutable();
		}

		if (const AccessInfo *Info = State_->Harvester.Find(Address))
		{
			Out.bReferenced = true;
			Out.Access.Total = Info->Count;
			Out.Access.PointerWide = Info->WideAccesses;
			Out.Access.Narrow = Info->NarrowAccesses;
			Out.Access.RankedTotal = State_->RankedCount;
			Out.Access.bAddressTaken = Info->HasKind(EAccessKind::AddressTaken);
			Out.Access.bIndirectBase = Info->HasKind(EAccessKind::IndirectBase);
			Out.Access.bLoaded = Info->HasKind(EAccessKind::Load);
			Out.Access.bStored = Info->HasKind(EAccessKind::Store);
			Out.Access.Offsets.assign(Info->Offsets.begin(), Info->Offsets.end());

			const auto It = State_->AccessRank.find(Address);
			Out.Access.Rank = It == State_->AccessRank.end() ? 0u : It->second;
		}

		// Every registered target is asked, not only the one a caller had in mind: a
		// name table that also verifies as an object array explains a cross-target
		// mix-up that a single verdict would not.
		Out.Targets.reserve(State_->Targets.size());
		for (const Analysis::TargetAnalysis &T : State_->Targets)
		{
			Out.Targets.push_back(AssessAddress(T.Strategy->Name(), Address));
		}

		return Out;
	}

	std::vector<std::string> UEAnalyzer::TargetNames() const
	{
		std::vector<std::string> Names;
		if (!State_)
			return Names;

		Names.reserve(State_->Targets.size());
		for (const Analysis::TargetAnalysis &T : State_->Targets)
		{
			Names.emplace_back(T.Strategy->Name());
		}
		return Names;
	}

	LayoutDescription UEAnalyzer::MakeLayoutDescription(const StructureEvidence &Evidence, uint64_t Address) const
	{
		LayoutDescription Out;
		Out.Layout = Evidence.Layout;

		if (Evidence.PrimaryFieldOffset >= 0)
		{
			Out.Table.Offset = Evidence.PrimaryFieldOffset;
			Out.Table.Reads = Evidence.PrimaryFieldAccesses;
			Out.Table.Width = static_cast<uint8_t>(sizeof(uintptr_t));
			Out.bValid = true;
		}

		for (int64_t Off : Evidence.Fields)
		{
			const AccessInfo *Info = State_->Harvester.Find(Address + static_cast<uint64_t>(Off));
			if (!Info || Info->NarrowAccesses == 0)
				continue;
			Out.Counts.push_back(LayoutField{Off, Info->NarrowAccesses, 4});
			Out.bValid = true;
		}
		return Out;
	}

	ETCharKind UEAnalyzer::GetTCharKind() const
	{
		return State_ ? State_->TChar : ETCharKind::Unknown;
	}

	size_t UEAnalyzer::GetTCharSize() const
	{
		switch (GetTCharKind())
		{
		case ETCharKind::Char16:
			return 2;
		case ETCharKind::Char32:
			return 4;
		default:
			return 0;
		}
	}

	UEAnalyzer::TargetDigest UEAnalyzer::DescribeTarget(const char *TargetName) const
	{
		TargetDigest Out;
		if (!State_)
			return Out;

		Out.DecodedInstructions = State_->Harvester.GetDecodedCount();
		Out.GlobalAccesses = State_->Harvester.GetAccesses().size();
		Out.RankedGlobals = State_->RankedCount;

		const Analysis::TargetAnalysis *Found = FindTarget(*State_, TargetName);
		if (!Found)
			return Out;

		const StringAnchors::EncodingHits &Hits = Found->Anchors.GetEncodingHits();
		Out.bFound = true;
		Out.FoundAnchors = Found->Anchors.GetFoundNames();
		Out.AnchorAddresses = Found->Anchors.GetAnchorAddresses().size();
		Out.AnchorCodeSites = Found->AnchorSites.size();
		Out.NarrowHits = Hits.Narrow;
		Out.Utf16Hits = Hits.Utf16;
		Out.Utf32Hits = Hits.Utf32;
		return Out;
	}

	std::vector<UEAnalyzer::ResolutionTrace> UEAnalyzer::ExplainResolution(const char *TargetName) const
	{
		std::vector<ResolutionTrace> Out;
		if (!State_ || !Memory_ || !State_->Arch)
			return Out;

		const Analysis::TargetAnalysis *Found = FindTarget(*State_, TargetName);
		if (!Found || !Found->Strategy)
			return Out;

		AnchoredResolution Anchored(Memory_, State_->Module, State_->Harvester, *State_->Arch, &State_->Calls, &State_->ResolutionSites, &State_->EhFrame);
		Anchored.Resolve(*Found->Strategy, Options_.Weights);
		Out.reserve(Anchored.GetTraces().size());
		for (const AnchoredResolution::AnchorTrace &Trace : Anchored.GetTraces())
		{
			ResolutionTrace Row;
			Row.Anchor = Trace.Which && Trace.Which->Text ? Trace.Which->Text : "";
			Row.Sites = Trace.Sites;
			Row.Applied = Trace.Applied;
			Row.Rejected = Trace.Rejected;
			Row.NoPick = Trace.NoPick;
			Row.Skip = Trace.Skip ? Trace.Skip : "";
			Row.RejectedSamples = Trace.RejectedDetail;
			Out.push_back(std::move(Row));
		}
		return Out;
	}

	LocateResult UEAnalyzer::Find(const char *TargetName, const CandidateValidator &Validator) const
	{
		return Run(TargetName, Validator);
	}

	LocateResult UEAnalyzer::Run(const char *TargetName, const CandidateValidator &Validator) const
	{
		LocateResult Result;

		if (!State_ || !Memory_ || !TargetName)
			return Result;

		Analysis *State = State_.get();

		// The strategies are asked which of them answers to this name, so a target is
		// identified by the one string it already publishes rather than by its
		// position in a list.
		const Analysis::TargetAnalysis *Found = nullptr;
		for (const Analysis::TargetAnalysis &Entry : State->Targets)
		{
			if (std::strcmp(Entry.Strategy->Name(), TargetName) == 0)
			{
				Found = &Entry;
				break;
			}
		}
		if (!Found)
			return Result;

		const Analysis::TargetAnalysis &T = *Found;
		const IStrategy &Strategy = *T.Strategy;
		Result.Target = Strategy.Name();

		AnalysisContext Ctx = State->MakeContext(T, Memory_, Options_.Weights);
		// A caller asking for more candidates than a strategy keeps by default gets
		// them; the trim is a cost bound, not a limit on the answer.
		Ctx.MaxScored = std::max(Options_.MaxCandidates, kMaxScoredCandidates);

		const bool bWantAnchored = !Options_.Method || *Options_.Method == EFindMethod::Anchored;
		const bool bWantLeads = !Options_.Method || *Options_.Method == EFindMethod::Statistical;

		// Tier 1: anchored resolution. A verified answer here is the answer; the
		// statistical path below exists only to offer leads when nothing verifies,
		// and its output is never presented as a result.
		if (State->Arch && bWantAnchored)
		{
			AnchoredResolution Anchored(Memory_, State->Module, State->Harvester, *State->Arch, &State->Calls, &State->ResolutionSites, &State->EhFrame);
			std::vector<Candidate> Verified = Anchored.Resolve(Strategy, Options_.Weights);

			// Structure verification says the shape is right; it does not say the
			// evidence is sufficient. A single instance of the weakest anchor can
			// clear verification and still land on the wrong global, with nothing
			// corroborating it. Hold the anchored tier to the same confidence gate as
			// everything else and let those fall through to labelled leads.
			Verified.erase(std::remove_if(Verified.begin(), Verified.end(), [&](const Candidate &C)
										  { return C.Confidence < Options_.Weights.MinConfidence; }),
						   Verified.end());

			ApplyValidator(Verified, Validator);

			if (!Verified.empty())
			{
				Result.Candidates = std::move(Verified);
				// A strategy that does not claim verification still contributes its
				// ranked candidates - they are the best leads available - but none of
				// them is presented as the answer.
				Result.bVerified = Strategy.ClaimsVerification();
				Result.FindMethod = EFindMethod::Anchored;
				if (Result.Candidates.size() > Options_.MaxCandidates)
					Result.Candidates.resize(Options_.MaxCandidates);
				return Result;
			}
		}

		if (!bWantLeads)
			return Result;

		// Tier 2: statistical leads. Nothing here is an answer, only a ranked list a
		// human can work through, which is why the result is labelled unverified.
		//
		// One strategy per target, so there is nothing to fuse across and no prior
		// to apply: an engine-version hint would be a caller's claim this tool
		// cannot check.
		Result.Candidates = Scoring::FuseCandidates(Strategy.Score(Ctx), Options_.Weights);
		ApplyValidator(Result.Candidates, Validator);
		Result.bVerified = false;
		Result.FindMethod = EFindMethod::Statistical;
		if (Result.Candidates.size() > Options_.MaxCandidates)
			Result.Candidates.resize(Options_.MaxCandidates);

		return Result;
	}

} // namespace nextdumper::analyzer
