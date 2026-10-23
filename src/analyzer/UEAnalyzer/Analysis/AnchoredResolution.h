#pragma once

#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "../../Memory/IMemory.h"
#include "../Core/Candidate.h"
#include "../Core/Scoring.h"

#include "AnchorTable.h"
#include "CallGraph.h"
#include "FunctionBoundary.h"
#include "GlobalAccessHarvester.h"

class IArchDecoder;

namespace nextdumper::analyzer
{

	class GlobalAccessHarvester;
	class IStrategy;
	class LiteralScanBatch;
	class EhFrameIndex;

	/**
	 * @brief One anchored resolution, kept for explainability and cross-checking.
	 */
	struct AnchorHit
	{
		const Anchor *Which = nullptr; ///< Anchor that produced this hit.
		uint64_t StringAddress = 0;	   ///< Where the anchor literal lives.
		uint64_t SiteAddress = 0;	   ///< Instruction that references the literal.
		FunctionBounds Function;	   ///< Function the site belongs to.
		uint64_t Container = 0;		   ///< Address-taken base, when the rule found one.
		int64_t MemberOffset = -1;	   ///< Derived from the code, never assumed.
		uint64_t Result = 0;		   ///< The resolved global.
		bool bViaCaller = false;	   ///< Container came from a caller's argument.

		/// The target was identified by reconstructing its layout: the function
		/// allocates N bytes, stores the pointer, and reads the structure's counts
		/// back at N-8. Far stronger than picking a global out of a function.
		bool bReconstructedLayout = false;

		std::string Evidence; ///< Why the structure check accepted it.
	};

	/**
	 * @brief Locates a global by finding a function that must touch it.
	 *
	 * This replaces ranking ~200,000 candidates with picking from the handful a
	 * single identified function uses: an anchored function typically touches
	 * only a couple of globals, which is why the choice becomes tractable.
	 *
	 * Nothing here encodes a byte pattern or a fixed structure offset: the anchor is
	 * a string the engine itself emits, and the member offset is derived from how
	 * the function actually accesses the container.
	 */
	class AnchoredResolution
	{
	public:
		using AnchorSites = std::map<std::pair<std::string, EAnchorMatch>, std::vector<uint64_t>>;
		static AnchorSites ScanAnchorSites(const IMemory *Memory, const ModuleInfo &Module,
										   const GlobalAccessHarvester &Harvester, std::span<const Anchor *const> Anchors);
		/// Copies needles and keys; only the output Literals is borrowed until Batch.Run().
		static void QueueAnchorLiterals(LiteralScanBatch &Batch, std::span<const Anchor *const> Anchors, AnchorSites &Literals);
		static AnchorSites MapAnchorSites(const AnchorSites &Literals, const GlobalAccessHarvester &Harvester);
		/**
		 * @param Memory     Backend to read code and strings from.
		 * @param Module    The caller's own GetUnrealModule() result - fetched once and
		 *                  shared, rather than re-fetched here on every construction.
		 * @param Harvester Shared access map from the whole-image pass.
		 * @param Arch      Decoder for the module's architecture.
		 * @param Calls     Optional call graph; without it the rules that resolve
		 *                  through callers cannot run.
		 * @param EhFrame   Optional .eh_frame_hdr index; when present, function
		 *                  bounds come from the compiler's unwind table rather than
		 *                  the instruction-scanning heuristic.
		 */
		AnchoredResolution(IMemory *Memory, const ModuleInfo &Module, const GlobalAccessHarvester &Harvester, const IArchDecoder &Arch, const CallGraph *Calls = nullptr, const AnchorSites *Sites = nullptr, const EhFrameIndex *EhFrame = nullptr)
			: Memory_(Memory),
			  Module_(Module),
			  Harvester_(Harvester),
			  Arch_(Arch),
			  Calls_(Calls),
			  SharedSites_(Sites),
			  EhFrame_(EhFrame)
		{
		}

		/**
		 * @brief Resolves one target through every anchor that applies to it.
		 * @return Candidates, best first. Empty when no anchor resolved.
		 */
		std::vector<Candidate> Resolve(const IStrategy &Strategy, const ScoringWeights &Weights) const;

		/// Every resolution attempt that produced an address, in the order tried.
		const std::vector<AnchorHit> &GetHits() const { return Hits_; }

		/**
		 * @brief Why each anchor did or did not contribute.
		 *
		 * Kept because "no result" needs to be diagnosable without a debugger; this is
		 * what `explain_anchors` prints.
		 */
		struct AnchorTrace
		{
			const Anchor *Which = nullptr; ///< Anchor this trace describes.
			size_t Sites = 0;			   ///< Code sites referencing the literal.
			size_t Applied = 0;			   ///< Sites that produced a verified result.
			size_t Rejected = 0;		   ///< Picked a global that failed verification.

			/// Sites where the rule could not choose a global at all - a different
			/// failure from choosing one that then failed verification, and the two
			/// need entirely different fixes.
			size_t NoPick = 0;

			const char *Skip = nullptr; ///< Why the anchor never ran, when it did not.

			/// A few rejected results with the verifier's reason, so "rejected" can be
			/// read as "picked X, refused because Y" instead of just a count.
			std::vector<std::pair<uint64_t, std::string>> RejectedDetail;
		};

		/// One trace per anchor considered for the last Resolve() call.
		const std::vector<AnchorTrace> &GetTraces() const { return Traces_; }

	private:
		/// Function bounds for an anchor site, computed once per site.
		///
		/// The boundary scan is the expensive part of resolution and the same sites
		/// are looked up by the cluster pass, the site filter and the pick rules.
		FunctionBounds BoundsFor(uint64_t Site) const;

		/// Whether Fn is the function this target's anchors overwhelmingly agree on.
		///
		/// Gates rules that are only sound on a function an anchor genuinely
		/// identifies. A rule such as SingleVerified picks the one verifying global
		/// a function touches, which is right for the function the anchors name and
		/// wrong for any small function that merely mentions the string.
		bool IsClusterLeader(const FunctionBounds &Fn) const;

		/// Resolves a table that the anchored function allocates and stores.
		///
		/// UE <= 4.22 builds GNames in FName::StaticInit rather than receiving it:
		/// the function allocates N bytes, stores the pointer into the global, then
		/// reads its counts back at N-8 and N-4 - TNameEntryArray being
		/// `FNameEntry** Chunks[]; int32 NumElements; int32 NumChunks`. That
		/// correspondence between allocation size and dereference offset is what
		/// separates the table from the mutex and flag the same function stores.
		///
		/// @return false when no stored global shows the correspondence, or when
		///         more than one does.
		bool ResolveViaAllocatedTable(const IStrategy &Strategy, const FunctionBounds &Fn, AnchorHit &Out) const;

		/// Counts, per function, how many distinct anchors reference it.
		void BuildAnchorCluster(const IStrategy &Strategy) const;

		mutable std::unordered_map<uint64_t, FunctionBounds> BoundsCache_;
		mutable std::unordered_map<uint64_t, int> AnchorsPerFunction_;
		mutable uint64_t ClusterLeader_ = 0;
		mutable int ClusterLeaderCount_ = 0;
		mutable int ClusterRunnerUp_ = 0;

		/**
		 * @brief Every code site that materializes the address of Text, in any encoding.
		 *
		 * @param Text Anchor literal, as ASCII; UTF-16 and UTF-32 forms are derived.
		 * @param bWholeStringOnly Require the match to be a standalone, NUL-delimited
		 *        literal rather than a substring. Essential for short engine words:
		 *        a name like "ByteProperty" also occurs as a substring inside
		 *        mangled C++ symbols such as _ZN13UByteProperty11StaticClassEv,
		 *        which live in the symbol string table and are referenced by
		 *        nothing - and can exhaust the per-segment hit cap before the real
		 *        literal is reached.
		 */
		const std::vector<uint64_t> &FindAnchorSites(const char *Text, EAnchorMatch Match = EAnchorMatch::Substring) const;

		/**
		 * @brief Applies an anchor's pick rule at one site.
		 * @return false when the rule could not choose a global, or the choice failed
		 *         structure verification.
		 */
		bool Apply(const IStrategy &Strategy, const Anchor &A, uint64_t Site, AnchorHit &Out) const;

		/**
		 * @brief Derives which offset from Container holds the object array.
		 *
		 * Scores each offset the function actually loads from the container by how
		 * much it behaves like a TUObjectArray header: a pointer at its own +0, small
		 * 32-bit counts just above it, and a chunk-size constant nearby. The offsets
		 * considered are the ones present in the binary, so a fork that reorders
		 * FUObjectArray still resolves.
		 *
		 * @param Local The caller's own ScanFunction(Fn.Start, Fn.End) result - callers
		 * already have this, so it is taken rather than rescanned.
		 */
		bool DeriveMember(uint64_t Container, const AccessMap &Local, uint64_t &OutMember, int64_t &OutOffset) const;

		/**
		 * @brief Resolves a member function's target through its callers.
		 *
		 * The most precise anchors sit inside member functions, which reach the
		 * global via `this` and never name it. The offset is derived from how the
		 * function uses `this`; the base comes from what a caller passes in X0.
		 */
		/**
		 * @brief Recovers `this` from what the anchored function's callers pass in X0.
		 *
		 * @param bSelfIsTarget True when the object itself is the answer, so no member
		 *        is derived and the offset is 0. False when the target is a member of
		 *        it, which is how the object array is reached.
		 */
		bool ResolveViaCaller(const FunctionBounds &Fn, AnchorHit &Out, bool bSelfIsTarget = false) const;

		/// Offset off the incoming `this` register that behaves like the array.
		bool DeriveThisOffset(const FunctionBounds &Fn, int64_t &OutOffset) const;

		/**
		 * @brief Recovers the target from the first argument of the calls a function makes.
		 *
		 * The mirror of ResolveViaCaller: that one reads X0 at *callers* of the
		 * anchored function to recover its `this`, this one reads X0 at the calls the
		 * anchored function *makes*, to recover what it hands to its helpers. This
		 * is how the name pool is typically reached.
		 */
		bool ResolveViaCalleeArgument(const IStrategy &Strategy, const FunctionBounds &Fn, AnchorHit &Out) const;

		IMemory *Memory_;
		ModuleInfo Module_;
		const GlobalAccessHarvester &Harvester_;
		const IArchDecoder &Arch_;
		const CallGraph *Calls_ = nullptr;
		const AnchorSites *SharedSites_ = nullptr;
		const EhFrameIndex *EhFrame_ = nullptr;
		mutable AnchorSites LocalSites_;
		mutable std::vector<AnchorHit> Hits_;
		mutable std::vector<AnchorTrace> Traces_;
	};

} // namespace nextdumper::analyzer
