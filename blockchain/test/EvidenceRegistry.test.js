const { expect } = require("chai");
const { ethers } = require("hardhat");
const { time, loadFixture } = require("@nomicfoundation/hardhat-network-helpers");

const Role = { None: 0, Investigator: 1, Analyst: 2, Court: 3 };
const Status = { InCustody: 0, Admitted: 1, Inadmissible: 2 };
const Action = {
  Collected: 0,
  Derived: 1,
  TransferInitiated: 2,
  TransferCancelled: 3,
  TransferAccepted: 4,
  CheckPassed: 5,
  CheckFailed: 6,
  AnalysisReport: 7,
  Admitted: 8,
  Inadmissible: 9,
};

// The contract only sees fingerprints. In the web app they are computed from the real file
// bytes (SHA-256 with Web Crypto, SHA3-256 with js-sha3); here two distinct digests per "file".
const sha256 = (text) => ethers.sha256(ethers.toUtf8Bytes(text));
const sha3 = (text) => ethers.keccak256(ethers.toUtf8Bytes("sha3:" + text));
const LOG = "203.0.113.45 - - [14/Sep/2026:02:14:07] POST /admin/login 302";

describe("EvidenceRegistry", function () {
  async function deployFixture() {
    const [authority, cyberCell, station7, lab, court, outsider, lab2] = await ethers.getSigners();
    const reg = await ethers.deployContract("EvidenceRegistry", [], authority);
    await reg.registerMember(cyberCell.address, Role.Investigator, "Cyber Crime Cell - North");
    await reg.registerMember(station7.address, Role.Investigator, "City Police Station 7");
    await reg.registerMember(lab.address, Role.Analyst, "Regional Forensic Science Lab");
    await reg.registerMember(court.address, Role.Court, "District Court Registry (demo)");
    await reg.registerMember(lab2.address, Role.Analyst, "Second Forensic Lab");
    return { reg, authority, cyberCell, station7, lab, court, outsider, lab2 };
  }

  /** A case with one piece of evidence (#1, the server log) held by the Cyber Crime Cell. */
  async function evidenceFixture() {
    const f = await deployFixture();
    await f.reg.connect(f.cyberCell).createCase("CC-2026-0147", "Unauthorised access to the billing portal");
    const collectedAt = (await time.latest()) - 3600;
    await f.reg
      .connect(f.cyberCell)
      .registerEvidence(1, sha256(LOG), sha3(LOG), "web01_access.log", 6144, "Web-server access log", collectedAt, 0);
    return { ...f, collectedAt };
  }

  /** Evidence #1 handed over to the lab and accepted with the correct hash. */
  async function atLabFixture() {
    const f = await evidenceFixture();
    await f.reg.connect(f.cyberCell).initiateTransfer(1, f.lab.address, "Forensic examination");
    await f.reg.connect(f.lab).acceptTransfer(1, sha256(LOG));
    return f;
  }

  /** Evidence #1 travelled cyber cell -> lab -> court and the court accepted it. */
  async function atCourtFixture() {
    const f = await atLabFixture();
    await f.reg.connect(f.lab).initiateTransfer(1, f.court.address, "Submission for trial");
    await f.reg.connect(f.court).acceptTransfer(1, sha256(LOG));
    return f;
  }

  describe("Consortium membership", function () {
    it("only the State Forensic Authority can register members", async function () {
      const { reg, outsider } = await loadFixture(deployFixture);
      await expect(reg.connect(outsider).registerMember(outsider.address, Role.Investigator, "Fake Unit"))
        .to.be.revertedWithCustomError(reg, "NotAdmin");
      const [accounts, info] = await reg.getMembers();
      expect(accounts.length).to.equal(5);
      expect(info[2].name).to.equal("Regional Forensic Science Lab");
      expect(info[2].role).to.equal(Role.Analyst);
    });

    it("rejects invalid and duplicate members", async function () {
      const { reg, authority, cyberCell, outsider } = await loadFixture(deployFixture);
      await expect(reg.registerMember(ethers.ZeroAddress, Role.Court, "X")).to.be.revertedWithCustomError(reg, "InvalidMember");
      await expect(reg.registerMember(outsider.address, Role.None, "X")).to.be.revertedWithCustomError(reg, "InvalidMember");
      await expect(reg.registerMember(outsider.address, Role.Court, "")).to.be.revertedWithCustomError(reg, "InvalidMember");
      await expect(reg.registerMember(authority.address, Role.Court, "Self")).to.be.revertedWithCustomError(reg, "InvalidMember");
      await expect(reg.registerMember(cyberCell.address, Role.Analyst, "Again"))
        .to.be.revertedWithCustomError(reg, "AlreadyRegistered")
        .withArgs(cyberCell.address);
    });

    it("suspended members cannot act until re-activated", async function () {
      const { reg, cyberCell, outsider } = await loadFixture(deployFixture);
      await expect(reg.setMemberActive(cyberCell.address, false)).to.emit(reg, "MemberStatusChanged").withArgs(cyberCell.address, false);
      await expect(reg.connect(cyberCell).createCase("CC-1", "Case"))
        .to.be.revertedWithCustomError(reg, "NotActiveMember")
        .withArgs(cyberCell.address);
      await reg.setMemberActive(cyberCell.address, true);
      await expect(reg.connect(cyberCell).createCase("CC-1", "Case")).to.emit(reg, "CaseCreated");
      await expect(reg.setMemberActive(outsider.address, true)).to.be.revertedWithCustomError(reg, "InvalidMember");
      await expect(reg.connect(outsider).setMemberActive(cyberCell.address, false)).to.be.revertedWithCustomError(reg, "NotAdmin");
    });
  });

  describe("Cases", function () {
    it("investigators open cases with unique case numbers", async function () {
      const { reg, cyberCell, station7 } = await loadFixture(deployFixture);
      await expect(reg.connect(cyberCell).createCase("CC-2026-0147", "Billing portal intrusion"))
        .to.emit(reg, "CaseCreated")
        .withArgs(1, "CC-2026-0147", "Billing portal intrusion", cyberCell.address);
      const c = await reg.getCase(1);
      expect(c.caseNumber).to.equal("CC-2026-0147");
      expect(c.createdBy).to.equal(cyberCell.address);
      expect(await reg.caseCount()).to.equal(1);
      await expect(reg.connect(station7).createCase("CC-2026-0147", "Copy"))
        .to.be.revertedWithCustomError(reg, "DuplicateCaseNumber")
        .withArgs(1);
      await expect(reg.connect(station7).createCase("", "No number")).to.be.revertedWithCustomError(reg, "InvalidCase");
      await expect(reg.getCase(2)).to.be.revertedWithCustomError(reg, "UnknownCase").withArgs(2);
    });

    it("only active investigators can open cases", async function () {
      const { reg, lab, court, outsider } = await loadFixture(deployFixture);
      await expect(reg.connect(lab).createCase("X-1", "X")).to.be.revertedWithCustomError(reg, "NotInvestigator");
      await expect(reg.connect(court).createCase("X-1", "X")).to.be.revertedWithCustomError(reg, "NotInvestigator");
      await expect(reg.connect(outsider).createCase("X-1", "X")).to.be.revertedWithCustomError(reg, "NotActiveMember");
    });
  });

  describe("Evidence registration (dual hashing)", function () {
    it("stores both hashes, starts ids at 1 and makes the collector the first custodian", async function () {
      const { reg, cyberCell, collectedAt } = await loadFixture(evidenceFixture);
      const e = await reg.getEvidence(1);
      expect(e.sha256Hash).to.equal(sha256(LOG));
      expect(e.sha3Hash).to.equal(sha3(LOG));
      expect(e.custodian).to.equal(cyberCell.address);
      expect(e.collectedAt).to.equal(collectedAt);
      expect(e.status).to.equal(Status.InCustody);
      expect(e.parentId).to.equal(0);
      expect(await reg.evidenceCount()).to.equal(1);
      expect(await reg.getCaseEvidence(1)).to.deep.equal([1n]);

      // Either fingerprint finds the record; an unknown hash returns 0.
      expect(await reg.findByHash(sha256(LOG))).to.equal(1);
      expect(await reg.findByHash(sha3(LOG))).to.equal(1);
      expect(await reg.findByHash(sha256(LOG + " "))).to.equal(0);

      const log = await reg.getCustodyLog(1);
      expect(log.length).to.equal(1);
      expect(log[0].action).to.equal(Action.Collected);
      expect(log[0].to).to.equal(cyberCell.address);
      expect(log[0].hash).to.equal(sha256(LOG));
    });

    it("emits EvidenceRegistered and rejects the same file again by either hash", async function () {
      const { reg, cyberCell, station7 } = await loadFixture(evidenceFixture);
      const t = (await time.latest()) - 60;
      await expect(reg.connect(station7).registerEvidence(1, sha256("cctv"), sha3("cctv"), "cam03.png", 90000, "CCTV still", t, 0))
        .to.emit(reg, "EvidenceRegistered")
        .withArgs(2, 1, 0, sha256("cctv"), sha3("cctv"), "cam03.png", station7.address);
      await expect(reg.connect(cyberCell).registerEvidence(1, sha256(LOG), sha3("other"), "copy.log", 1, "", t, 0))
        .to.be.revertedWithCustomError(reg, "DuplicateEvidence")
        .withArgs(1);
      await expect(reg.connect(cyberCell).registerEvidence(1, sha256("other"), sha3(LOG), "copy.log", 1, "", t, 0))
        .to.be.revertedWithCustomError(reg, "DuplicateEvidence")
        .withArgs(1);
    });

    it("rejects a collection time in the future until the chain reaches it", async function () {
      const { reg, cyberCell } = await loadFixture(evidenceFixture);
      const future = (await time.latest()) + 3600;
      await expect(reg.connect(cyberCell).registerEvidence(1, sha256("chat"), sha3("chat"), "chat.txt", 10, "Chat export", future, 0))
        .to.be.revertedWithCustomError(reg, "CollectedInFuture");
      await time.increaseTo(future);
      await expect(reg.connect(cyberCell).registerEvidence(1, sha256("chat"), sha3("chat"), "chat.txt", 10, "Chat export", future, 0))
        .to.emit(reg, "EvidenceRegistered");
    });

    it("rejects unknown cases and incomplete fingerprints", async function () {
      const { reg, cyberCell } = await loadFixture(evidenceFixture);
      const t = (await time.latest()) - 60;
      await expect(reg.connect(cyberCell).registerEvidence(7, sha256("a"), sha3("a"), "a", 1, "", t, 0))
        .to.be.revertedWithCustomError(reg, "UnknownCase")
        .withArgs(7);
      await expect(reg.connect(cyberCell).registerEvidence(1, ethers.ZeroHash, sha3("a"), "a", 1, "", t, 0))
        .to.be.revertedWithCustomError(reg, "InvalidEvidence");
      await expect(reg.connect(cyberCell).registerEvidence(1, sha256("a"), ethers.ZeroHash, "a", 1, "", t, 0))
        .to.be.revertedWithCustomError(reg, "InvalidEvidence");
      await expect(reg.connect(cyberCell).registerEvidence(1, sha256("a"), sha3("a"), "", 1, "", t, 0))
        .to.be.revertedWithCustomError(reg, "InvalidEvidence");
      await expect(reg.connect(cyberCell).registerEvidence(1, sha256("a"), sha3("a"), "a", 1, "", 0, 0))
        .to.be.revertedWithCustomError(reg, "InvalidEvidence");
    });

    it("only investigators register original evidence", async function () {
      const { reg, lab, court, outsider } = await loadFixture(evidenceFixture);
      const t = (await time.latest()) - 60;
      await expect(reg.connect(lab).registerEvidence(1, sha256("a"), sha3("a"), "a", 1, "", t, 0))
        .to.be.revertedWithCustomError(reg, "NotInvestigator");
      await expect(reg.connect(outsider).registerEvidence(1, sha256("a"), sha3("a"), "a", 1, "", t, 0))
        .to.be.revertedWithCustomError(reg, "NotActiveMember");
      // Courts cannot register derived evidence either, even of an item they hold.
      await expect(reg.connect(court).registerEvidence(1, sha256("a"), sha3("a"), "a", 1, "", t, 1))
        .to.be.revertedWithCustomError(reg, "NotInvestigatorOrAnalyst");
    });
  });

  describe("Two-step custody transfer", function () {
    it("moves custody only after the receiver presents the matching hash", async function () {
      const { reg, cyberCell, lab } = await loadFixture(evidenceFixture);
      await expect(reg.connect(cyberCell).initiateTransfer(1, lab.address, "Forensic examination"))
        .to.emit(reg, "TransferInitiated")
        .withArgs(1, cyberCell.address, lab.address, "Forensic examination");
      let e = await reg.getEvidence(1);
      expect(e.pendingTo).to.equal(lab.address);
      expect(e.custodian).to.equal(cyberCell.address); // still with the sender while in transit

      await expect(reg.connect(lab).acceptTransfer(1, sha256(LOG)))
        .to.emit(reg, "TransferAccepted")
        .withArgs(1, cyberCell.address, lab.address, sha256(LOG));
      e = await reg.getEvidence(1);
      expect(e.custodian).to.equal(lab.address);
      expect(e.pendingTo).to.equal(ethers.ZeroAddress);
      expect(e.lastCheckOk).to.equal(true);
      expect(e.lastCheckBy).to.equal(lab.address);

      const log = await reg.getCustodyLog(1);
      expect(log.map((r) => Number(r.action))).to.deep.equal([Action.Collected, Action.TransferInitiated, Action.TransferAccepted]);
      expect(log[2].from).to.equal(cyberCell.address);
      expect(log[2].to).to.equal(lab.address);
      expect(log[2].note).to.equal("Forensic examination");
    });

    it("a tampered copy is refused with IntegrityMismatch and custody does not move", async function () {
      const { reg, cyberCell, lab } = await loadFixture(evidenceFixture);
      await reg.connect(cyberCell).initiateTransfer(1, lab.address, "Forensic examination");
      const tampered = sha256(LOG.replace("203.0.113.45", "203.0.113.46"));
      await expect(reg.connect(lab).acceptTransfer(1, tampered))
        .to.be.revertedWithCustomError(reg, "IntegrityMismatch")
        .withArgs(sha256(LOG), tampered);
      const e = await reg.getEvidence(1);
      expect(e.custodian).to.equal(cyberCell.address);
      expect(e.pendingTo).to.equal(lab.address);
    });

    it("enforces who may hand over evidence and to whom", async function () {
      const { reg, authority, cyberCell, station7, lab, outsider } = await loadFixture(evidenceFixture);
      await expect(reg.connect(station7).initiateTransfer(1, lab.address, "x"))
        .to.be.revertedWithCustomError(reg, "NotCustodian")
        .withArgs(cyberCell.address);
      await expect(reg.connect(cyberCell).initiateTransfer(1, cyberCell.address, "x")).to.be.revertedWithCustomError(reg, "InvalidRecipient");
      await expect(reg.connect(cyberCell).initiateTransfer(1, outsider.address, "x"))
        .to.be.revertedWithCustomError(reg, "RecipientNotActive")
        .withArgs(outsider.address);
      await expect(reg.connect(cyberCell).initiateTransfer(1, authority.address, "x")).to.be.revertedWithCustomError(reg, "RecipientNotActive");
      await reg.setMemberActive(lab.address, false);
      await expect(reg.connect(cyberCell).initiateTransfer(1, lab.address, "x")).to.be.revertedWithCustomError(reg, "RecipientNotActive");
      await reg.setMemberActive(lab.address, true);
      await expect(reg.connect(cyberCell).initiateTransfer(1, lab.address, "")).to.be.revertedWithCustomError(reg, "ReasonRequired");
      await reg.connect(cyberCell).initiateTransfer(1, lab.address, "Forensic examination");
      await expect(reg.connect(cyberCell).initiateTransfer(1, station7.address, "x"))
        .to.be.revertedWithCustomError(reg, "TransferAlreadyPending")
        .withArgs(lab.address);
    });

    it("only the named receiver can accept, and only while a transfer is pending", async function () {
      const { reg, cyberCell, station7, lab } = await loadFixture(evidenceFixture);
      await expect(reg.connect(lab).acceptTransfer(1, sha256(LOG))).to.be.revertedWithCustomError(reg, "NoPendingTransfer");
      await reg.connect(cyberCell).initiateTransfer(1, lab.address, "Forensic examination");
      await expect(reg.connect(station7).acceptTransfer(1, sha256(LOG)))
        .to.be.revertedWithCustomError(reg, "NotRecipient")
        .withArgs(lab.address);
      await expect(reg.connect(lab).acceptTransfer(9, sha256(LOG)))
        .to.be.revertedWithCustomError(reg, "UnknownEvidence")
        .withArgs(9);
    });

    it("the sender can withdraw and the receiver can refuse a hand-over", async function () {
      const { reg, cyberCell, station7, lab } = await loadFixture(evidenceFixture);
      await reg.connect(cyberCell).initiateTransfer(1, lab.address, "Forensic examination");
      await expect(reg.connect(station7).cancelTransfer(1)).to.be.revertedWithCustomError(reg, "NotTransferParty");
      await expect(reg.connect(lab).cancelTransfer(1)).to.emit(reg, "TransferCancelled").withArgs(1, lab.address);
      await expect(reg.connect(lab).cancelTransfer(1)).to.be.revertedWithCustomError(reg, "NoPendingTransfer");

      await reg.connect(cyberCell).initiateTransfer(1, station7.address, "Joint investigation");
      await expect(reg.connect(cyberCell).cancelTransfer(1)).to.emit(reg, "TransferCancelled").withArgs(1, cyberCell.address);
      const log = await reg.getCustodyLog(1);
      expect(log[2].action).to.equal(Action.TransferCancelled);
      expect(log[2].note).to.equal("refused by the receiver");
      expect(log[4].note).to.equal("withdrawn by the sender");
      expect((await reg.getEvidence(1)).custodian).to.equal(cyberCell.address);
    });
  });

  describe("Integrity checks (tamper alarm)", function () {
    it("a matching check is logged; a mismatch raises a permanent tamper alarm", async function () {
      const { reg, cyberCell, station7, outsider } = await loadFixture(evidenceFixture);
      await expect(reg.connect(station7).recordIntegrityCheck(1, sha256(LOG), "routine re-hash"))
        .to.emit(reg, "IntegrityChecked")
        .withArgs(1, station7.address, sha256(LOG), true);
      let e = await reg.getEvidence(1);
      expect(e.flagged).to.equal(false);
      expect(e.lastCheckOk).to.equal(true);

      const bad = sha256(LOG + "\n");
      await expect(reg.connect(cyberCell).recordIntegrityCheck(1, bad, "copy on the shared drive"))
        .to.emit(reg, "IntegrityChecked")
        .withArgs(1, cyberCell.address, bad, false);
      // A later good check does not erase the alarm: the history stays on-chain.
      await reg.connect(cyberCell).recordIntegrityCheck(1, sha256(LOG), "original re-checked");
      e = await reg.getEvidence(1);
      expect(e.flagged).to.equal(true);
      expect(e.failedChecks).to.equal(1);
      expect(e.lastCheckOk).to.equal(true);
      const log = await reg.getCustodyLog(1);
      expect(log.map((r) => Number(r.action))).to.deep.equal([Action.Collected, Action.CheckPassed, Action.CheckFailed, Action.CheckPassed]);
      expect(log[2].hash).to.equal(bad);
      expect(log[2].note).to.equal("copy on the shared drive");

      await expect(reg.connect(outsider).recordIntegrityCheck(1, sha256(LOG), "x")).to.be.revertedWithCustomError(reg, "NotActiveMember");
    });
  });

  describe("Forensic analysis and derived evidence", function () {
    it("the analyst holding the evidence anchors report hashes", async function () {
      const { reg, lab, cyberCell, lab2 } = await loadFixture(atLabFixture);
      const report = sha256("FSL report on evidence #1");
      await expect(reg.connect(lab).addAnalysisReport(1, report, "37 failed logins, then an admin session"))
        .to.emit(reg, "AnalysisReportAdded")
        .withArgs(1, lab.address, report, "37 failed logins, then an admin session");
      expect(await reg.findReport(report)).to.equal(1);
      expect((await reg.getEvidence(1)).reportCount).to.equal(1);

      await expect(reg.connect(lab).addAnalysisReport(1, report, "again"))
        .to.be.revertedWithCustomError(reg, "DuplicateReport")
        .withArgs(1);
      await expect(reg.connect(lab).addAnalysisReport(1, ethers.ZeroHash, "x")).to.be.revertedWithCustomError(reg, "InvalidReport");
      await expect(reg.connect(lab).addAnalysisReport(1, sha256("r2"), "")).to.be.revertedWithCustomError(reg, "InvalidReport");
      await expect(reg.connect(lab2).addAnalysisReport(1, sha256("r2"), "x"))
        .to.be.revertedWithCustomError(reg, "NotCustodian")
        .withArgs(lab.address);
      await expect(reg.connect(cyberCell).addAnalysisReport(1, sha256("r2"), "x")).to.be.revertedWithCustomError(reg, "NotAnalyst");
    });

    it("derived evidence is linked to a parent the analyst holds, in the same case", async function () {
      const { reg, lab, lab2, cyberCell } = await loadFixture(atLabFixture);
      const t = (await time.latest()) - 10;
      await expect(reg.connect(lab).registerEvidence(1, sha256("extract"), sha3("extract"), "extract.log", 900, "Requests from 203.0.113.45", t, 1))
        .to.emit(reg, "EvidenceRegistered")
        .withArgs(2, 1, 1, sha256("extract"), sha3("extract"), "extract.log", lab.address);
      const d = await reg.getEvidence(2);
      expect(d.parentId).to.equal(1);
      expect(d.custodian).to.equal(lab.address);
      expect((await reg.getCustodyLog(2))[0].action).to.equal(Action.Derived);

      await expect(reg.connect(lab2).registerEvidence(1, sha256("x"), sha3("x"), "x", 1, "", t, 1))
        .to.be.revertedWithCustomError(reg, "NotCustodian")
        .withArgs(lab.address);
      await expect(reg.connect(lab).registerEvidence(1, sha256("x"), sha3("x"), "x", 1, "", t, 5))
        .to.be.revertedWithCustomError(reg, "UnknownEvidence")
        .withArgs(5);
      await reg.connect(cyberCell).createCase("CC-2026-0200", "Another case");
      await expect(reg.connect(lab).registerEvidence(2, sha256("x"), sha3("x"), "x", 1, "", t, 1))
        .to.be.revertedWithCustomError(reg, "ParentCaseMismatch")
        .withArgs(1);
    });
  });

  describe("Court decisions", function () {
    it("admits verified evidence it holds, after which the record is closed", async function () {
      const { reg, court, lab } = await loadFixture(atCourtFixture);
      await expect(reg.connect(court).admitEvidence(1)).to.emit(reg, "EvidenceAdmitted").withArgs(1, court.address);
      const e = await reg.getEvidence(1);
      expect(e.status).to.equal(Status.Admitted);
      const log = await reg.getCustodyLog(1);
      expect(log[log.length - 1].action).to.equal(Action.Admitted);

      await expect(reg.connect(court).admitEvidence(1))
        .to.be.revertedWithCustomError(reg, "EvidenceClosed")
        .withArgs(Status.Admitted);
      await expect(reg.connect(court).initiateTransfer(1, lab.address, "Return")).to.be.revertedWithCustomError(reg, "EvidenceClosed");
    });

    it("refuses admission without custody, with a pending hand-over or for non-courts", async function () {
      const { reg, court, lab, cyberCell } = await loadFixture(atLabFixture);
      await expect(reg.connect(lab).admitEvidence(1)).to.be.revertedWithCustomError(reg, "NotCourt");
      await expect(reg.connect(court).admitEvidence(1))
        .to.be.revertedWithCustomError(reg, "NotCustodian")
        .withArgs(lab.address);
      await reg.connect(lab).initiateTransfer(1, court.address, "Submission for trial");
      await reg.connect(court).acceptTransfer(1, sha256(LOG));
      await reg.connect(court).initiateTransfer(1, cyberCell.address, "Further investigation");
      await expect(reg.connect(court).admitEvidence(1))
        .to.be.revertedWithCustomError(reg, "TransferAlreadyPending")
        .withArgs(cyberCell.address);
    });

    it("never admits evidence with a tamper alarm on record", async function () {
      const { reg, court, cyberCell } = await loadFixture(atCourtFixture);
      await reg.connect(cyberCell).recordIntegrityCheck(1, sha256("altered copy"), "copy found on a USB stick");
      await reg.connect(court).recordIntegrityCheck(1, sha256(LOG), "court re-hash");
      await expect(reg.connect(court).admitEvidence(1))
        .to.be.revertedWithCustomError(reg, "TamperAlarm")
        .withArgs(1);
    });

    it("requires the latest integrity check to be the court's own matching check", async function () {
      const { reg, court, station7 } = await loadFixture(atCourtFixture);
      await reg.connect(station7).recordIntegrityCheck(1, sha256(LOG), "defence request");
      await expect(reg.connect(court).admitEvidence(1)).to.be.revertedWithCustomError(reg, "NotVerifiedByCourt");
      await reg.connect(court).recordIntegrityCheck(1, sha256(LOG), "re-hash before ruling");
      await expect(reg.connect(court).admitEvidence(1)).to.emit(reg, "EvidenceAdmitted");
    });

    it("rules evidence inadmissible with a reason and stops any pending hand-over", async function () {
      const { reg, court, lab, cyberCell } = await loadFixture(atLabFixture);
      await reg.connect(lab).initiateTransfer(1, court.address, "Submission for trial");
      await expect(reg.connect(court).markInadmissible(1, "")).to.be.revertedWithCustomError(reg, "ReasonRequired");
      await expect(reg.connect(cyberCell).markInadmissible(1, "x")).to.be.revertedWithCustomError(reg, "NotCourt");
      await expect(reg.connect(court).markInadmissible(1, "Chain of custody broken"))
        .to.emit(reg, "EvidenceInadmissible")
        .withArgs(1, court.address, "Chain of custody broken");
      const e = await reg.getEvidence(1);
      expect(e.status).to.equal(Status.Inadmissible);
      expect(e.pendingTo).to.equal(ethers.ZeroAddress);
      await expect(reg.connect(court).acceptTransfer(1, sha256(LOG))).to.be.revertedWithCustomError(reg, "NoPendingTransfer");
      await expect(reg.connect(lab).addAnalysisReport(1, sha256("late report"), "x"))
        .to.be.revertedWithCustomError(reg, "EvidenceClosed")
        .withArgs(Status.Inadmissible);
    });
  });

  describe("Audit trail", function () {
    it("custody records carry the block time of each step", async function () {
      const { reg, cyberCell, lab } = await loadFixture(evidenceFixture);
      const t1 = (await time.latest()) + 7200;
      await time.setNextBlockTimestamp(t1);
      await reg.connect(cyberCell).initiateTransfer(1, lab.address, "Forensic examination");
      await time.increase(1800);
      await reg.connect(lab).acceptTransfer(1, sha256(LOG));
      const log = await reg.getCustodyLog(1);
      expect(log[1].time).to.equal(t1);
      expect(log[2].time).to.be.greaterThanOrEqual(t1 + 1800);
      expect((await reg.getEvidence(1)).lastCheckAt).to.equal(log[2].time);
      await expect(reg.getCustodyLog(0)).to.be.revertedWithCustomError(reg, "UnknownEvidence").withArgs(0);
      await expect(reg.getCaseEvidence(3)).to.be.revertedWithCustomError(reg, "UnknownCase").withArgs(3);
    });
  });
});
