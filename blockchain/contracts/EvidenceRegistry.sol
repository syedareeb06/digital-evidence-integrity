// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title EvidenceRegistry - Blockchain-Based Digital Evidence Integrity (CustodyChain)
/// @notice A permissioned consortium shares one chain-of-custody register for digital
///         evidence (CCTV stills, server logs, chat exports, disk images):
///           - the State Forensic Authority (admin, the deployer) registers and suspends members,
///           - investigators open cases and register the evidence they collect,
///           - forensic analysts examine evidence, attach reports and register derived evidence,
///           - courts verify evidence and rule it admitted or inadmissible.
///         Only fingerprints are stored: the SHA-256 AND the SHA3-256 hash of every file
///         (dual hashing: two unrelated designs, Merkle-Damgard and the Keccak sponge), so a
///         forger would need a simultaneous collision in both. The files stay off-chain.
/// @dev Every hand-over is two-step. The custodian initiates it; the receiver accepts it only
///      by presenting the SHA-256 of the copy it actually received, and the contract compares
///      it with the registered hash. A wrong hash reverts with IntegrityMismatch; the receiver
///      then calls recordIntegrityCheck so the failed check is kept forever as a tamper alarm.
///      Case and evidence ids start at 1, so 0 means "none" (no parent / not found).
contract EvidenceRegistry {
    enum Role { None, Investigator, Analyst, Court }
    enum Status { InCustody, Admitted, Inadmissible }
    enum Action {
        Collected,          // original evidence registered by the investigator who seized it
        Derived,            // derived evidence (e.g. an extract or enhanced copy) registered
        TransferInitiated,  // custodian started a hand-over
        TransferCancelled,  // hand-over withdrawn by the sender or refused by the receiver
        TransferAccepted,   // receiver re-hashed its copy, hash matched, custody moved
        CheckPassed,        // integrity check: presented hash matches
        CheckFailed,        // integrity check: presented hash does NOT match (tamper alarm)
        AnalysisReport,     // analyst anchored the hash of an analysis report
        Admitted,           // court admitted the evidence
        Inadmissible        // court ruled the evidence inadmissible
    }

    struct Member {
        Role role;
        string name;
        bool active;
    }

    struct Case {
        string caseNumber;  // e.g. "CC-2026-0147" (unique)
        string title;
        address createdBy;
        uint64 createdAt;
    }

    struct Evidence {
        uint256 caseId;
        uint256 parentId;       // 0 = original evidence, otherwise the evidence it was derived from
        bytes32 sha256Hash;     // SHA-256 (FIPS 180-4) of the exact file bytes
        bytes32 sha3Hash;       // SHA3-256 (FIPS 202) of the exact file bytes
        string fileName;
        string description;
        uint64 sizeBytes;
        uint64 collectedAt;     // when the evidence was seized / created (never in the future)
        uint64 registeredAt;    // block time of registration
        address registeredBy;
        address custodian;      // who holds the evidence now
        Status status;
        bool flagged;           // tamper alarm: at least one integrity check failed (permanent)
        uint32 failedChecks;
        uint32 reportCount;
        bool lastCheckOk;       // result of the most recent integrity check (hand-overs count)
        address lastCheckBy;
        uint64 lastCheckAt;
        address pendingTo;      // receiver of the pending hand-over (0 = none)
        string pendingPurpose;
        uint64 pendingSince;
    }

    /// @notice One line of the tamper-evident custody log.
    struct CustodyRecord {
        Action action;
        address from;
        address to;
        uint64 time;
        string note;
        bytes32 hash;   // evidence hash, presented hash or report hash, depending on the action
    }

    /// @notice The State Forensic Authority: manages the consortium.
    address public immutable admin;

    mapping(address => Member) public members;
    address[] private memberList;

    uint256 public caseCount;
    mapping(uint256 => Case) private cases;
    mapping(bytes32 => uint256) private caseByNumber;      // keccak256(caseNumber) => caseId
    mapping(uint256 => uint256[]) private caseEvidence;

    uint256 public evidenceCount;
    mapping(uint256 => Evidence) private evidences;
    mapping(uint256 => CustodyRecord[]) private custodyLog;
    mapping(bytes32 => uint256) private evidenceByHash;    // SHA-256 or SHA3-256 => evidenceId
    mapping(bytes32 => uint256) private reportOf;          // report hash => evidenceId

    event MemberRegistered(address indexed account, Role role, string name);
    event MemberStatusChanged(address indexed account, bool active);
    event CaseCreated(uint256 indexed caseId, string caseNumber, string title, address indexed by);
    event EvidenceRegistered(
        uint256 indexed evidenceId,
        uint256 indexed caseId,
        uint256 parentId,
        bytes32 sha256Hash,
        bytes32 sha3Hash,
        string fileName,
        address indexed by
    );
    event TransferInitiated(uint256 indexed evidenceId, address indexed from, address indexed to, string purpose);
    event TransferCancelled(uint256 indexed evidenceId, address indexed by);
    event TransferAccepted(uint256 indexed evidenceId, address indexed from, address indexed to, bytes32 verifiedHash);
    event IntegrityChecked(uint256 indexed evidenceId, address indexed by, bytes32 presentedHash, bool matched);
    event AnalysisReportAdded(uint256 indexed evidenceId, address indexed analyst, bytes32 reportHash, string summary);
    event EvidenceAdmitted(uint256 indexed evidenceId, address indexed court);
    event EvidenceInadmissible(uint256 indexed evidenceId, address indexed court, string reason);

    error NotAdmin();
    error InvalidMember();
    error AlreadyRegistered(address account);
    error NotActiveMember(address account);
    error NotInvestigator();
    error NotAnalyst();
    error NotCourt();
    error NotInvestigatorOrAnalyst();
    error UnknownCase(uint256 caseId);
    error UnknownEvidence(uint256 evidenceId);
    error InvalidCase();
    error DuplicateCaseNumber(uint256 caseId);
    error InvalidEvidence();
    error DuplicateEvidence(uint256 evidenceId);
    error CollectedInFuture(uint64 collectedAt, uint256 nowTime);
    error ParentCaseMismatch(uint256 parentCaseId);
    error NotCustodian(address custodian);
    error InvalidRecipient();
    error RecipientNotActive(address account);
    error TransferAlreadyPending(address pendingTo);
    error NoPendingTransfer();
    error NotRecipient(address expected);
    error NotTransferParty();
    error IntegrityMismatch(bytes32 registered, bytes32 presented);
    error EvidenceClosed(Status status);
    error InvalidReport();
    error DuplicateReport(uint256 evidenceId);
    error TamperAlarm(uint32 failedChecks);
    error NotVerifiedByCourt();
    error ReasonRequired();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // ------------------------------------------------------------------
    // Consortium membership (Module IV: permissioned participants with roles)
    // ------------------------------------------------------------------

    /// @notice The State Forensic Authority admits a police unit, forensic lab or court.
    function registerMember(address account, Role role, string calldata name) external onlyAdmin {
        if (account == address(0) || account == admin || role == Role.None || bytes(name).length == 0) revert InvalidMember();
        if (members[account].role != Role.None) revert AlreadyRegistered(account);
        members[account] = Member(role, name, true);
        memberList.push(account);
        emit MemberRegistered(account, role, name);
    }

    /// @notice Suspend or re-activate a member. Suspended members keep their history but cannot act.
    function setMemberActive(address account, bool active) external onlyAdmin {
        if (members[account].role == Role.None) revert InvalidMember();
        members[account].active = active;
        emit MemberStatusChanged(account, active);
    }

    // ------------------------------------------------------------------
    // Cases and evidence
    // ------------------------------------------------------------------

    /// @notice An investigator opens a case. Case numbers are unique.
    function createCase(string calldata caseNumber, string calldata title) external returns (uint256 caseId) {
        if (_activeMember(msg.sender).role != Role.Investigator) revert NotInvestigator();
        if (bytes(caseNumber).length == 0 || bytes(title).length == 0) revert InvalidCase();
        bytes32 key = keccak256(bytes(caseNumber));
        if (caseByNumber[key] != 0) revert DuplicateCaseNumber(caseByNumber[key]);

        caseId = ++caseCount;
        cases[caseId] = Case(caseNumber, title, msg.sender, uint64(block.timestamp));
        caseByNumber[key] = caseId;
        emit CaseCreated(caseId, caseNumber, title, msg.sender);
    }

    /// @notice Register a piece of evidence by its two fingerprints. The caller becomes its first custodian.
    /// @param parentId 0 for original evidence (investigators only). Otherwise the id of the evidence it
    ///        was derived from: the caller (investigator or analyst) must currently hold that parent.
    function registerEvidence(
        uint256 caseId,
        bytes32 sha256Hash,
        bytes32 sha3Hash,
        string calldata fileName,
        uint64 sizeBytes,
        string calldata description,
        uint64 collectedAt,
        uint256 parentId
    ) external returns (uint256 evidenceId) {
        _checkRegistration(caseId, parentId);
        if (sha256Hash == 0 || sha3Hash == 0 || bytes(fileName).length == 0 || collectedAt == 0) revert InvalidEvidence();
        // The same file can only be registered once, whichever of its two hashes is looked up.
        if (evidenceByHash[sha256Hash] != 0) revert DuplicateEvidence(evidenceByHash[sha256Hash]);
        if (evidenceByHash[sha3Hash] != 0) revert DuplicateEvidence(evidenceByHash[sha3Hash]);
        if (collectedAt > block.timestamp) revert CollectedInFuture(collectedAt, block.timestamp);

        evidenceId = ++evidenceCount;
        Evidence storage e = evidences[evidenceId];
        e.caseId = caseId;
        e.parentId = parentId;
        e.sha256Hash = sha256Hash;
        e.sha3Hash = sha3Hash;
        e.fileName = fileName;
        e.description = description;
        e.sizeBytes = sizeBytes;
        e.collectedAt = collectedAt;
        e.registeredAt = uint64(block.timestamp);
        e.registeredBy = msg.sender;
        e.custodian = msg.sender;
        _indexAndLog(evidenceId, e);
    }

    // ------------------------------------------------------------------
    // Two-step custody transfer
    // ------------------------------------------------------------------

    /// @notice Step 1: the current custodian hands the evidence to another active member.
    function initiateTransfer(uint256 evidenceId, address to, string calldata purpose) external {
        _activeMember(msg.sender);
        Evidence storage e = _open(evidenceId);
        if (e.custodian != msg.sender) revert NotCustodian(e.custodian);
        if (e.pendingTo != address(0)) revert TransferAlreadyPending(e.pendingTo);
        if (to == address(0) || to == msg.sender) revert InvalidRecipient();
        Member storage r = members[to];
        if (r.role == Role.None || !r.active) revert RecipientNotActive(to);
        if (bytes(purpose).length == 0) revert ReasonRequired();

        e.pendingTo = to;
        e.pendingPurpose = purpose;
        e.pendingSince = uint64(block.timestamp);
        _log(evidenceId, Action.TransferInitiated, msg.sender, to, purpose, bytes32(0));
        emit TransferInitiated(evidenceId, msg.sender, to, purpose);
    }

    /// @notice Withdraw a pending hand-over (sender) or refuse it (receiver).
    function cancelTransfer(uint256 evidenceId) external {
        Evidence storage e = _evidence(evidenceId);
        address to = e.pendingTo;
        if (to == address(0)) revert NoPendingTransfer();
        if (msg.sender != e.custodian && msg.sender != to) revert NotTransferParty();
        _clearPending(e);
        _log(evidenceId, Action.TransferCancelled, e.custodian, to, msg.sender == to ? "refused by the receiver" : "withdrawn by the sender", bytes32(0));
        emit TransferCancelled(evidenceId, msg.sender);
    }

    /// @notice Step 2: the receiver re-hashes the copy it received and presents the SHA-256.
    ///         Custody only moves if it equals the registered hash, so the receiver proves it
    ///         holds an intact copy. A wrong hash reverts and nothing changes.
    function acceptTransfer(uint256 evidenceId, bytes32 sha256Check) external {
        _activeMember(msg.sender);
        Evidence storage e = _evidence(evidenceId);
        if (e.pendingTo == address(0)) revert NoPendingTransfer();
        if (e.pendingTo != msg.sender) revert NotRecipient(e.pendingTo);
        if (sha256Check != e.sha256Hash) revert IntegrityMismatch(e.sha256Hash, sha256Check);

        address from = e.custodian;
        string memory purpose = e.pendingPurpose;
        e.custodian = msg.sender;
        _clearPending(e);
        _setLastCheck(e, true);
        _log(evidenceId, Action.TransferAccepted, from, msg.sender, purpose, sha256Check);
        emit TransferAccepted(evidenceId, from, msg.sender, sha256Check);
    }

    /// @notice Any active member records a re-hash of a copy it holds. A mismatch raises a
    ///         permanent tamper alarm that every later viewer (and the court) will see.
    function recordIntegrityCheck(uint256 evidenceId, bytes32 sha256Check, string calldata note) external returns (bool matched) {
        _activeMember(msg.sender);
        Evidence storage e = _evidence(evidenceId);
        matched = sha256Check == e.sha256Hash;
        _setLastCheck(e, matched);
        if (!matched) {
            e.flagged = true;
            e.failedChecks += 1;
        }
        _log(evidenceId, matched ? Action.CheckPassed : Action.CheckFailed, msg.sender, address(0), note, sha256Check);
        emit IntegrityChecked(evidenceId, msg.sender, sha256Check, matched);
    }

    // ------------------------------------------------------------------
    // Forensic analysis and court decisions
    // ------------------------------------------------------------------

    /// @notice The analyst holding the evidence anchors the hash of its analysis report.
    function addAnalysisReport(uint256 evidenceId, bytes32 reportHash, string calldata summary) external {
        if (_activeMember(msg.sender).role != Role.Analyst) revert NotAnalyst();
        Evidence storage e = _open(evidenceId);
        if (e.custodian != msg.sender) revert NotCustodian(e.custodian);
        if (reportHash == 0 || bytes(summary).length == 0) revert InvalidReport();
        if (reportOf[reportHash] != 0) revert DuplicateReport(reportOf[reportHash]);

        reportOf[reportHash] = evidenceId;
        e.reportCount += 1;
        _log(evidenceId, Action.AnalysisReport, msg.sender, address(0), summary, reportHash);
        emit AnalysisReportAdded(evidenceId, msg.sender, reportHash, summary);
    }

    /// @notice A court admits evidence it holds. Allowed only if no tamper alarm was ever raised
    ///         and the most recent integrity check is a matching check made by this court
    ///         (accepting the hand-over counts as one).
    function admitEvidence(uint256 evidenceId) external {
        if (_activeMember(msg.sender).role != Role.Court) revert NotCourt();
        Evidence storage e = _open(evidenceId);
        if (e.custodian != msg.sender) revert NotCustodian(e.custodian);
        if (e.pendingTo != address(0)) revert TransferAlreadyPending(e.pendingTo);
        if (e.flagged) revert TamperAlarm(e.failedChecks);
        if (!e.lastCheckOk || e.lastCheckBy != msg.sender) revert NotVerifiedByCourt();

        e.status = Status.Admitted;
        _log(evidenceId, Action.Admitted, msg.sender, address(0), "admitted as evidence", e.sha256Hash);
        emit EvidenceAdmitted(evidenceId, msg.sender);
    }

    /// @notice A court rules evidence inadmissible (for example after a tamper alarm). Any pending
    ///         hand-over is cancelled: a decided item does not travel any further.
    function markInadmissible(uint256 evidenceId, string calldata reason) external {
        if (_activeMember(msg.sender).role != Role.Court) revert NotCourt();
        Evidence storage e = _open(evidenceId);
        if (bytes(reason).length == 0) revert ReasonRequired();
        if (e.pendingTo != address(0)) _clearPending(e);

        e.status = Status.Inadmissible;
        _log(evidenceId, Action.Inadmissible, msg.sender, address(0), reason, e.sha256Hash);
        emit EvidenceInadmissible(evidenceId, msg.sender, reason);
    }

    // ------------------------------------------------------------------
    // Views
    // ------------------------------------------------------------------

    function getCase(uint256 caseId) external view returns (Case memory) {
        if (caseId == 0 || caseId > caseCount) revert UnknownCase(caseId);
        return cases[caseId];
    }

    function getCaseEvidence(uint256 caseId) external view returns (uint256[] memory) {
        if (caseId == 0 || caseId > caseCount) revert UnknownCase(caseId);
        return caseEvidence[caseId];
    }

    function getEvidence(uint256 evidenceId) external view returns (Evidence memory) {
        return _evidence(evidenceId);
    }

    /// @notice The full, append-only chain of custody of one item.
    function getCustodyLog(uint256 evidenceId) external view returns (CustodyRecord[] memory) {
        _evidence(evidenceId);
        return custodyLog[evidenceId];
    }

    /// @notice Public verification: the evidence whose SHA-256 or SHA3-256 equals `hash` (0 = none).
    function findByHash(bytes32 hash) external view returns (uint256) {
        return evidenceByHash[hash];
    }

    /// @notice The evidence an analysis report (by its SHA-256) belongs to (0 = none).
    function findReport(bytes32 reportHash) external view returns (uint256) {
        return reportOf[reportHash];
    }

    function getMembers() external view returns (address[] memory accounts, Member[] memory info) {
        accounts = memberList;
        info = new Member[](memberList.length);
        for (uint256 i = 0; i < memberList.length; i++) info[i] = members[memberList[i]];
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    function _activeMember(address account) private view returns (Member storage m) {
        m = members[account];
        if (m.role == Role.None || !m.active) revert NotActiveMember(account);
    }

    function _evidence(uint256 evidenceId) private view returns (Evidence storage) {
        if (evidenceId == 0 || evidenceId > evidenceCount) revert UnknownEvidence(evidenceId);
        return evidences[evidenceId];
    }

    /// @dev Evidence that the court has not decided on yet.
    function _open(uint256 evidenceId) private view returns (Evidence storage e) {
        e = _evidence(evidenceId);
        if (e.status != Status.InCustody) revert EvidenceClosed(e.status);
    }

    /// @dev Role rules for registerEvidence: originals by investigators, derived evidence by the
    ///      investigator or analyst who holds the parent, always inside the parent's case.
    function _checkRegistration(uint256 caseId, uint256 parentId) private view {
        Role role = _activeMember(msg.sender).role;
        if (caseId == 0 || caseId > caseCount) revert UnknownCase(caseId);
        if (parentId == 0) {
            if (role != Role.Investigator) revert NotInvestigator();
            return;
        }
        if (role != Role.Investigator && role != Role.Analyst) revert NotInvestigatorOrAnalyst();
        Evidence storage parent = _open(parentId);
        if (parent.custodian != msg.sender) revert NotCustodian(parent.custodian);
        if (parent.caseId != caseId) revert ParentCaseMismatch(parent.caseId);
    }

    /// @dev Second half of registerEvidence (split off to keep the EVM stack small): index both
    ///      hashes for findByHash, add the item to its case, write the first custody record.
    function _indexAndLog(uint256 evidenceId, Evidence storage e) private {
        evidenceByHash[e.sha256Hash] = evidenceId;
        evidenceByHash[e.sha3Hash] = evidenceId;
        caseEvidence[e.caseId].push(evidenceId);
        _log(evidenceId, e.parentId == 0 ? Action.Collected : Action.Derived, address(0), msg.sender, e.description, e.sha256Hash);
        emit EvidenceRegistered(evidenceId, e.caseId, e.parentId, e.sha256Hash, e.sha3Hash, e.fileName, msg.sender);
    }

    function _setLastCheck(Evidence storage e, bool ok) private {
        e.lastCheckOk = ok;
        e.lastCheckBy = msg.sender;
        e.lastCheckAt = uint64(block.timestamp);
    }

    function _clearPending(Evidence storage e) private {
        e.pendingTo = address(0);
        e.pendingPurpose = "";
        e.pendingSince = 0;
    }

    function _log(uint256 evidenceId, Action action, address from, address to, string memory note, bytes32 hash) private {
        custodyLog[evidenceId].push(CustodyRecord(action, from, to, uint64(block.timestamp), note, hash));
    }
}
