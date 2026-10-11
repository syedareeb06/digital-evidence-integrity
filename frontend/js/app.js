/* CustodyChain - Blockchain-Based Digital Evidence Integrity System (web app) */
(function () {
  const ROLE = { None: 0, Investigator: 1, Analyst: 2, Court: 3 };
  const ROLE_LABEL = ["-", "Investigator", "Forensic analyst", "Court"];
  const STATUS = { InCustody: 0, Admitted: 1, Inadmissible: 2 };
  // Custody-log actions, in the order of EvidenceRegistry.Action
  const A = { Collected: 0, Derived: 1, TransferInitiated: 2, TransferCancelled: 3, TransferAccepted: 4, CheckPassed: 5, CheckFailed: 6, AnalysisReport: 7, Admitted: 8, Inadmissible: 9 };

  // Demo consortium: account 0 is the State Forensic Authority (contract deployer). All names are fictional.
  const CONSORTIUM = [
    [1, ROLE.Investigator, "Cyber Crime Cell - North"],
    [2, ROLE.Investigator, "City Police Station 7"],
    [3, ROLE.Analyst, "Regional Forensic Science Lab"],
    [4, ROLE.Court, "District Court Registry (demo)"],
  ];
  const CASE_IDEAS = [
    ["CC-2026-0147", "Unauthorised access to the municipal billing portal"],
    ["CC-2026-0152", "Fake electricity-bill SMS campaign"],
    ["PS7-2026-0311", "Laptop stolen from the ward office"],
  ];
  const NEW_MEMBERS = [
    ["Cyber Crime Cell - South", ROLE.Investigator],
    ["Mobile Forensics Unit", ROLE.Analyst],
    ["Sessions Court Registry (demo)", ROLE.Court],
    ["Railway Police Post 3", ROLE.Investigator],
  ];

  const MAX_UPLOAD = 10 * 1024 * 1024; // files are hashed in the browser up to this size
  const MAX_STORED = 512 * 1024; // larger files keep only their hashes (and a thumbnail) in this browser
  const ZERO_HASH = "0x" + "0".repeat(64);

  const ERRORS = {
    NotAdmin: () => "only the State Forensic Authority (account 0) can manage the consortium.",
    InvalidMember: () => "invalid member details (account, role and name are required).",
    AlreadyRegistered: (a) => `${Chain.label(a)} is already a consortium member.`,
    NotActiveMember: (a) => `${Chain.label(a)} is not an active consortium member (it may have been suspended by the State Forensic Authority).`,
    NotInvestigator: () => "only an investigator can open cases and register original evidence.",
    NotAnalyst: () => "only a forensic analyst can attach analysis reports.",
    NotCourt: () => "only a court can admit evidence or rule it inadmissible.",
    NotInvestigatorOrAnalyst: () => "only investigators and forensic analysts can register derived evidence.",
    UnknownCase: (id) => `case #${id} does not exist.`,
    UnknownEvidence: (id) => `evidence #${id} does not exist.`,
    InvalidCase: () => "a case number and a title are required.",
    DuplicateCaseNumber: (id) => `this case number is already used by case #${id}.`,
    InvalidEvidence: () => "both hashes, a file name and a collection time are required.",
    DuplicateEvidence: (id) => `this exact file is already registered as evidence #${id}.`,
    CollectedInFuture: (at, now) => `the collection time ${UI.fmtTime(at)} is later than the current block time ${UI.fmtTime(now)}.`,
    ParentCaseMismatch: (c) => `derived evidence must belong to the same case as its parent (case #${c}).`,
    NotCustodian: (c) => `only the current custodian (${Chain.label(c)}) can do this.`,
    InvalidRecipient: () => "choose another member as the receiver.",
    RecipientNotActive: (a) => `${Chain.label(a)} is not an active consortium member, so it cannot receive evidence.`,
    TransferAlreadyPending: (to) => `a hand-over to ${Chain.label(to)} is still pending. It must be accepted or cancelled first.`,
    NoPendingTransfer: () => "there is no pending hand-over for this evidence.",
    NotRecipient: (to) => `this hand-over is addressed to ${Chain.label(to)}.`,
    NotTransferParty: () => "only the sender or the receiver can cancel this hand-over.",
    IntegrityMismatch: (reg, pres) =>
      `integrity check failed. The SHA-256 of the received copy (${UI.short(pres, 6)}) does not match the registered hash (${UI.short(reg, 6)}), so custody was NOT transferred.`,
    EvidenceClosed: (s) => `the court has already ruled on this evidence (${["in custody", "admitted", "inadmissible"][Number(s)]}).`,
    InvalidReport: () => "a report hash and a one-line summary are required.",
    DuplicateReport: (id) => `this exact report is already attached to evidence #${id}.`,
    TamperAlarm: (n) => `admission refused: ${n} failed integrity check(s) (tamper alarm) on record for this evidence.`,
    NotVerifiedByCourt: () => "the court must verify the file itself first: the latest integrity check must be the court's own matching re-hash.",
    ReasonRequired: () => "please give a purpose or reason.",
  };

  const lower = (a) => (a || "").toLowerCase();
  const sameAddr = (a, b) => lower(a) === lower(b);
  const authority = () => Chain.accounts[0];
  const CC = () => window.CustodyCrypto;
  const ES = () => window.EvidenceSamples;
  const icon = (n) => Shell.icon(n);
  const esc = (v) => UI.esc(v);
  const fmtBytes = (n) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(2)} MB`);
  const pad = (n) => String(n).padStart(2, "0");
  const toLocalInput = (ts) => {
    const d = new Date(ts * 1000);
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  };
  const fromLocalInput = (v) => Math.floor(new Date(v).getTime() / 1000);
  const slug = (s) => String(s).replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "");
  const utf8 = new TextEncoder();

  /** An expected problem (bad input, missing file): shown as a toast, not logged as a bug. */
  function userError(message) {
    const e = new Error(message);
    e.revert = { name: "UserInput" };
    return e;
  }

  // ------------------------------------------------------------------
  // Data
  // ------------------------------------------------------------------
  async function load() {
    const c = Chain.contract;
    const [accts, infos] = await c.getMembers();
    const members = accts.map((a, i) => ({ address: a, role: Number(infos[i].role), name: infos[i].name, active: infos[i].active }));
    Chain.setName(authority(), "State Forensic Authority");
    members.forEach((m) => Chain.setName(m.address, m.name));

    const [nc, ne] = (await Promise.all([c.caseCount(), c.evidenceCount()])).map(Number);
    const cases = await Promise.all(
      Array.from({ length: nc }, async (_, i) => {
        const id = i + 1;
        const [k, ids] = await Promise.all([c.getCase(id), c.getCaseEvidence(id)]);
        return { id, number: k.caseNumber, title: k.title, createdBy: k.createdBy, createdAt: Number(k.createdAt), evidenceIds: ids.map(Number) };
      })
    );
    const evidence = await Promise.all(
      Array.from({ length: ne }, async (_, i) => {
        const id = i + 1;
        const [e, log] = await Promise.all([c.getEvidence(id), c.getCustodyLog(id)]);
        return {
          id,
          caseId: Number(e.caseId),
          parentId: Number(e.parentId),
          sha256: e.sha256Hash,
          sha3: e.sha3Hash,
          fileName: e.fileName,
          description: e.description,
          size: Number(e.sizeBytes),
          collectedAt: Number(e.collectedAt),
          registeredAt: Number(e.registeredAt),
          registeredBy: e.registeredBy,
          custodian: e.custodian,
          status: Number(e.status),
          flagged: e.flagged,
          failedChecks: Number(e.failedChecks),
          reportCount: Number(e.reportCount),
          lastCheckOk: e.lastCheckOk,
          lastCheckBy: e.lastCheckBy,
          lastCheckAt: Number(e.lastCheckAt),
          pendingTo: e.pendingTo === ethers.ZeroAddress ? null : e.pendingTo,
          pendingPurpose: e.pendingPurpose,
          pendingSince: Number(e.pendingSince),
          log: log.map((r) => ({ action: Number(r.action), from: r.from, to: r.to, time: Number(r.time), note: r.note, hash: r.hash })),
        };
      })
    );
    const caseById = new Map(cases.map((k) => [k.id, k]));
    const evById = new Map(evidence.map((e) => [e.id, e]));
    for (const e of evidence) {
      e.case = caseById.get(e.caseId);
      e.children = evidence.filter((x) => x.parentId === e.id).map((x) => x.id);
    }
    const byRole = (r) => members.filter((m) => m.role === r);
    return {
      members,
      investigators: byRole(ROLE.Investigator),
      analysts: byRole(ROLE.Analyst),
      courts: byRole(ROLE.Court),
      cases,
      evidence,
      ev: (id) => evById.get(Number(id)),
      kase: (id) => caseById.get(Number(id)),
    };
  }

  function status(e) {
    if (e.status === STATUS.Admitted) return { key: "admitted", label: "Admitted", chip: "chip-ok" };
    if (e.status === STATUS.Inadmissible) return { key: "inadmissible", label: "Inadmissible", chip: "chip-bad" };
    if (e.pendingTo) return { key: "transit", label: "Hand-over pending", chip: "chip-warn" };
    return { key: "custody", label: "In custody", chip: "chip-accent" };
  }
  const chips = (e) => {
    const st = status(e);
    return `<span class="row" style="gap:4px"><span class="chip ${st.chip}">${st.label}</span>${
      e.flagged ? `<span class="chip chip-bad" title="${e.failedChecks} failed integrity check(s)">Tamper alarm</span>` : ""
    }</span>`;
  };
  const activeChip = (m) => (m.active ? `<span class="chip chip-ok">Active</span>` : `<span class="chip chip-bad">Suspended</span>`);

  // ------------------------------------------------------------------
  // Off-chain storage (the "evidence locker": files, thumbnails, reports)
  // ------------------------------------------------------------------
  const files = () => Chain.store.get("files", {}); // sha256 -> { name, type, b64, sample, meta }
  const thumbs = () => Chain.store.get("thumbs", {}); // sha256 -> small JPEG data URL
  const reportStore = () => Chain.store.get("reports", {}); // report sha256 -> { name, type, b64, evidenceId }
  const transit = () => Chain.store.get("transit", {}); // evidenceId -> copy swapped in by the Tamper Lab
  const samplesUsed = () => Chain.store.get("samples", {}); // "caseId:kind" -> evidenceId
  function putIn(key, k, v) {
    const all = Chain.store.get(key, {});
    if (v === undefined) delete all[k];
    else all[k] = v;
    Chain.store.set(key, all);
  }
  const unpack = (f) => (f ? { bytes: UI.base64ToBytes(f.b64), type: f.type, name: f.name, sample: f.sample || null, meta: f.meta || null } : null);
  const storedFile = (e) => unpack(files()[e.sha256]);
  const caseCtx = (k) => ({ caseNumber: k.number, caseCreatedAt: k.createdAt });

  async function keepOffChain(file, fp) {
    const kept = [];
    if (ES().kindOf(file) === "image") {
      try {
        putIn("thumbs", fp.sha256, await ES().thumbnail(file.bytes, file.type));
        kept.push("a thumbnail");
      } catch {
        /* not decodable: no thumbnail */
      }
    }
    if (file.bytes.length <= MAX_STORED) {
      putIn("files", fp.sha256, { name: file.name, type: file.type, b64: UI.bytesToBase64(file.bytes), sample: file.sample || null, meta: file.meta || null });
      kept.unshift("the file");
    }
    return kept.length
      ? `${kept.join(" and ")} stay${kept.length > 1 ? "" : "s"} in this browser's evidence locker. Only the hashes and metadata are on-chain.`
      : `File larger than ${fmtBytes(MAX_STORED)}: only its hashes are kept. Receivers will upload their copy.`;
  }

  const sampleCache = {};
  function sampleFile(kind, k) {
    const key = `${Chain.address}|${k.id}|${kind}`;
    if (!sampleCache[key]) sampleCache[key] = ES().make(kind, caseCtx(k));
    return sampleCache[key];
  }

  /** Read an <input type=file>; null (with a toast) if unusable. */
  async function readInput(input) {
    const f = input.files && input.files[0];
    input.value = "";
    if (!f) return null;
    if (f.size > MAX_UPLOAD) {
      UI.toast(`"${f.name}" is ${fmtBytes(f.size)}. The limit is ${fmtBytes(MAX_UPLOAD)}.`, "error");
      return null;
    }
    if (!f.size) {
      UI.toast(`"${f.name}" is empty.`, "error");
      return null;
    }
    return { bytes: await UI.readFileBytes(f), type: f.type || "application/octet-stream", name: f.name };
  }

  /** Steps shown in the page's "Activity" card. */
  async function runWork(member, title, steps) {
    const t = document.getElementById("work-title");
    if (t) t.textContent = title;
    const run = await UI.runSteps(document.getElementById("work-steps"), steps);
    Shell.state.work = { member, title, items: run.items, scroll: true };
    return run;
  }

  // ------------------------------------------------------------------
  // Core actions
  // ------------------------------------------------------------------
  async function createCase(investigator, number, title) {
    const r = await Chain.send(investigator, "createCase", [number, title]);
    const id = Number(r.events.find((x) => x.name === "CaseCreated").args.caseId);
    UI.toast(`Case ${number} opened on-chain (case #${id})`, "success");
    return id;
  }

  /** Read -> SHA-256 -> SHA3-256 -> registerEvidence transaction -> keep the file off-chain. */
  async function registerEvidence(collector, file, { caseId, description, collectedAt, parentId = 0 }) {
    const fp = {};
    let id;
    const run = await runWork(collector, parentId ? `Register derived evidence (from #${parentId})` : "Register evidence", [
      { title: "Read the file in this browser (it is never uploaded)", run: async () => `${file.name} · ${fmtBytes(file.bytes.length)} · ${file.type || "unknown type"}` },
      { title: "Fingerprint 1: SHA-256 (FIPS 180-4)", run: async () => (fp.sha256 = await CC().sha256(file.bytes)) },
      { title: "Fingerprint 2: SHA3-256 (FIPS 202, Keccak sponge)", run: async () => (fp.sha3 = CC().sha3(file.bytes)) },
      {
        title: parentId ? `registerEvidence: record both hashes on-chain, linked to parent #${parentId}` : "registerEvidence: record both hashes on the blockchain",
        run: async () => {
          const r = await Chain.send(collector, "registerEvidence", [caseId, fp.sha256, fp.sha3, file.name, file.bytes.length, description, collectedAt, parentId]);
          id = Number(r.events.find((x) => x.name === "EvidenceRegistered").args.evidenceId);
          return `Evidence #${id} · block #${r.block.number} · tx ${UI.short(r.receipt.hash, 6)} · first custodian: ${Chain.label(collector)}`;
        },
      },
      { title: "Keep the file off-chain", run: async () => keepOffChain(file, fp) },
    ]);
    if (!run.ok) throw run.error;
    if (file.sample) putIn("samples", `${caseId}:${file.sample}`, id);
    UI.toast(`"${file.name}" registered as evidence #${id}${parentId ? ` (derived from #${parentId})` : ""}`, "success");
    return id;
  }

  /** Same as registerEvidence without the live steps (used by "Load sample case"). */
  async function quickRegister(collector, file, { caseId, description, collectedAt }) {
    const fp = await CC().fingerprint(file.bytes);
    const r = await Chain.send(collector, "registerEvidence", [caseId, fp.sha256, fp.sha3, file.name, file.bytes.length, description, collectedAt, 0]);
    await keepOffChain(file, fp);
    const id = Number(r.events.find((x) => x.name === "EvidenceRegistered").args.evidenceId);
    if (file.sample) putIn("samples", `${caseId}:${file.sample}`, id);
    return id;
  }

  /** Opens case CC-2026-0147 and registers the three built-in sample files (skips what exists). */
  async function loadDemoCase() {
    let data = await load();
    const [inv1, inv2] = [data.investigators[0], data.investigators[1] || data.investigators[0]];
    if (!inv1) throw userError("No investigator is registered.");
    const [number, title] = CASE_IDEAS[0];
    if (!data.cases.some((c) => c.number === number)) {
      await createCase(inv1.address, number, title);
      data = await load();
    }
    const k = data.cases.find((c) => c.number === number);
    const plan = [
      ["log", inv1, 5400],
      ["cctv", inv2, 7200],
      ["chat", inv1, 3600],
    ];
    const done = [];
    for (const [kind, who, ago] of plan) {
      const file = await sampleFile(kind, k);
      const fp = await CC().fingerprint(file.bytes);
      if (Number(await Chain.contract.findByHash(fp.sha256))) continue;
      done.push(await quickRegister(who.address, file, { caseId: k.id, description: file.description, collectedAt: Chain.now() - ago }));
    }
    UI.toast(
      done.length ? `Sample case ${number}: evidence ${done.map((d) => "#" + d).join(", ")} registered` : `Sample case ${number} is already loaded`,
      done.length ? "success" : "info"
    );
    return done;
  }

  async function initiateTransfer(from, evidenceId, to, purpose) {
    await Chain.send(from, "initiateTransfer", [evidenceId, to, purpose]);
    UI.toast(`Hand-over of #${evidenceId} to ${Chain.label(to)} started. The receiver must re-hash its copy to accept it.`, "success");
  }

  async function cancelTransfer(member, e) {
    const refused = sameAddr(member, e.pendingTo);
    await Chain.send(member, "cancelTransfer", [e.id]);
    putIn("transit", String(e.id), undefined);
    UI.toast(refused ? `Hand-over of #${e.id} refused` : `Hand-over of #${e.id} cancelled`, "success");
  }

  /** The copy that reached the receiver: normally the locker copy, unless the Tamper Lab swapped it. */
  function deliveredCopy(e) {
    const t = transit()[e.id];
    if (t && e.pendingSince && Number(t.since) === e.pendingSince) return { ...unpack(t), swapped: true };
    return storedFile(e);
  }

  /** Receiver re-hashes the copy it received; the contract moves custody only if the SHA-256 matches. */
  async function acceptTransfer(receiver, e, uploaded) {
    let copy, fp, result;
    const run = await runWork(receiver, `Accept evidence #${e.id} with a re-hash`, [
      {
        title: `Receive the copy sent by ${Chain.label(e.custodian)}`,
        run: async () => {
          copy = uploaded || deliveredCopy(e);
          if (!copy) throw userError('No copy of this file reached this browser. Use "Upload received file".');
          return `${copy.name} · ${fmtBytes(copy.bytes.length)}${uploaded ? " (uploaded by the receiver)" : ""}`;
        },
      },
      {
        title: "Re-hash the received copy (SHA-256 and SHA3-256)",
        run: async () => {
          fp = await CC().fingerprint(copy.bytes);
          return `SHA-256 ${UI.short(fp.sha256, 8)} · SHA3-256 ${UI.short(fp.sha3, 8)}`;
        },
      },
      {
        title: "Compare with the fingerprints registered on-chain",
        run: async () => {
          if (fp.sha256 === e.sha256 && fp.sha3 === e.sha3) return "Both hashes match the registered values";
          return `NO MATCH: ${CC().compare(fp.sha256, e.sha256).digits} of 64 SHA-256 digits and ${CC().compare(fp.sha3, e.sha3).digits} of 64 SHA3-256 digits differ. Sending it anyway: the smart contract decides.`;
        },
      },
      {
        title: "acceptTransfer: the contract compares the SHA-256 with the registered hash",
        run: async () => {
          try {
            result = await Chain.send(receiver, "acceptTransfer", [e.id, fp.sha256]);
          } catch (err) {
            if (!err.revert || err.revert.name !== "IntegrityMismatch") throw err;
            // The revert undid everything, so record the failed check in a separate transaction: a permanent tamper alarm.
            const alarm = await Chain.send(receiver, "recordIntegrityCheck", [
              e.id,
              fp.sha256,
              `Copy received from ${Chain.label(e.custodian)} failed the re-hash; hand-over not accepted`,
            ]);
            const x = new Error(`${err.message} Tamper alarm recorded on-chain (block #${alarm.block.number}).`);
            x.revert = err.revert;
            throw x;
          }
          return `Custody moved to ${Chain.label(receiver)} · block #${result.block.number} · tx ${UI.short(result.receipt.hash, 6)}`;
        },
      },
    ]);
    if (!run.ok) throw run.error;
    putIn("transit", String(e.id), undefined);
    if (uploaded && !files()[e.sha256]) await keepOffChain(uploaded, fp);
    UI.toast(`Evidence #${e.id} accepted: re-hash matched, ${Chain.label(receiver)} is now the custodian`, "success");
  }

  /** A member re-hashes the copy it holds and stores the result on-chain (pass, or tamper alarm). */
  async function verifyIntegrity(member, e, uploaded) {
    let copy, fp, matched;
    const run = await runWork(member, `Integrity check of evidence #${e.id}`, [
      {
        title: `Take the copy held by ${Chain.label(member)}`,
        run: async () => {
          copy = uploaded || storedFile(e);
          if (!copy) throw userError("This file is not in this browser's evidence locker.");
          return `${copy.name} · ${fmtBytes(copy.bytes.length)}`;
        },
      },
      {
        title: "Re-hash it (SHA-256 and SHA3-256)",
        run: async () => {
          fp = await CC().fingerprint(copy.bytes);
          return `SHA-256 ${UI.short(fp.sha256, 8)} · SHA3-256 ${UI.short(fp.sha3, 8)}`;
        },
      },
      {
        title: "Compare with the fingerprints registered on-chain",
        run: async () => {
          matched = fp.sha256 === e.sha256 && fp.sha3 === e.sha3;
          return matched ? "Both hashes match" : `Mismatch: ${CC().compare(fp.sha256, e.sha256).digits} of 64 SHA-256 digits differ`;
        },
      },
      {
        title: "recordIntegrityCheck: store the result on-chain",
        run: async () => {
          const r = await Chain.send(member, "recordIntegrityCheck", [
            e.id,
            fp.sha256,
            matched ? `Re-hash by ${Chain.label(member)}: intact` : `Copy held by ${Chain.label(member)} failed the re-hash`,
          ]);
          if (!matched) throw userError(`Tamper alarm recorded on-chain for evidence #${e.id} (block #${r.block.number}).`);
          return `Passed check recorded · block #${r.block.number}`;
        },
      },
    ]);
    if (!run.ok) throw run.error;
    UI.toast(`Evidence #${e.id} re-verified by ${Chain.label(member)}: intact`, "success");
  }

  function reportText(e, analyst, analysis, n) {
    const received = e.log.filter((r) => r.action === A.TransferAccepted && sameAddr(r.to, analyst)).slice(-1)[0];
    const lines = [
      `${Chain.label(analyst).toUpperCase()} - DIGITAL EVIDENCE ANALYSIS REPORT`,
      "(CustodyChain demo - fictional data)",
      "",
      `Report no.  : FSL/${e.case.number}/E${e.id}/R${n}`,
      `Case        : ${e.case.number} - ${e.case.title}`,
      `Evidence    : #${e.id} ${e.fileName} (${fmtBytes(e.size)})`,
      `Received    : ${received ? `from ${Chain.label(received.from)} on ${UI.fmtTime(received.time)}; re-hash matched the on-chain record` : "registered by the lab"}`,
      `SHA-256     : ${e.sha256}`,
      `SHA3-256    : ${e.sha3}`,
      `Examiner    : ${Chain.label(analyst)}`,
      `Date        : ${UI.fmtTime(Chain.now())}`,
      "",
      "METHOD",
      `Both hashes of the working copy were re-computed before the examination and matched. ${analysis.method}`,
      "",
      "FINDINGS",
      ...analysis.findings.map((f, i) => `${i + 1}. ${f}`),
      "",
      "CONCLUSION",
      `${analysis.summary}.`,
      "",
      "The SHA-256 of this report is anchored on the CustodyChain register (addAnalysisReport).",
      "Any later change to this text will no longer match it.",
    ];
    return lines.join("\n") + "\n";
  }

  /** Analyst writes a report (or uploads one) and anchors its SHA-256 on-chain. */
  async function addReport(analyst, e, uploaded) {
    let file, analysis, report, hash;
    const steps = uploaded
      ? [
          {
            title: "Read the report file",
            run: async () => {
              report = uploaded;
              return `${uploaded.name} · ${fmtBytes(uploaded.bytes.length)}`;
            },
          },
        ]
      : [
          {
            title: "Re-hash the working copy before examining it",
            run: async () => {
              file = storedFile(e);
              if (!file) throw userError("The evidence file is not in this browser. Upload your own report instead.");
              const fp = await CC().fingerprint(file.bytes);
              if (fp.sha256 !== e.sha256 || fp.sha3 !== e.sha3) throw userError("The locker copy does not match the registered hashes. Do not examine it.");
              return "Both hashes match the on-chain record";
            },
          },
          {
            title: "Examine the file",
            run: async () => {
              analysis = await ES().analyse(file);
              return analysis.summary;
            },
          },
          {
            title: "Write the analysis report (kept off-chain)",
            run: async () => {
              const text = reportText(e, analyst, analysis, e.reportCount + 1);
              report = { name: `FSL-${slug(e.case.number)}-E${e.id}-R${e.reportCount + 1}.txt`, type: "text/plain", bytes: utf8.encode(text), summary: analysis.summary };
              return `${report.name} · ${text.split("\n").length} lines`;
            },
          },
        ];
    steps.push(
      { title: "SHA-256 of the report", run: async () => (hash = await CC().sha256(report.bytes)) },
      {
        title: "addAnalysisReport: anchor the report hash on-chain",
        run: async () => {
          const r = await Chain.send(analyst, "addAnalysisReport", [e.id, hash, String(report.summary).slice(0, 180)]);
          if (report.bytes.length <= MAX_STORED) putIn("reports", hash, { name: report.name, type: report.type || "text/plain", b64: UI.bytesToBase64(report.bytes), evidenceId: e.id });
          return `Block #${r.block.number}. Only the hash and the one-line summary are on-chain.`;
        },
      }
    );
    const run = await runWork(analyst, `Analysis report for evidence #${e.id}`, steps);
    if (!run.ok) throw run.error;
    UI.toast(`Analysis report for #${e.id} anchored on-chain`, "success");
    return hash;
  }

  /** Lab registers derived evidence (generated extract, or an uploaded file) linked to its parent. */
  async function deriveEvidence(member, e, uploaded) {
    let derived = uploaded;
    if (!derived) {
      const file = storedFile(e);
      if (!file) throw userError("The evidence file is not in this browser. Upload the derived file instead.");
      derived = await ES().derive(file, caseCtx(e.case));
      if (!derived) throw userError("There is no built-in extraction for this file type. Upload the derived file instead.");
    }
    return registerEvidence(member, derived, {
      caseId: e.caseId,
      description: derived.description || `Derived from evidence #${e.id}`,
      collectedAt: Chain.now() - 30,
      parentId: e.id,
    });
  }

  async function admit(court, e) {
    await Chain.send(court, "admitEvidence", [e.id]);
    Shell.state.cert = e.id;
    UI.toast(`Evidence #${e.id} admitted by ${Chain.label(court)}`, "success");
  }

  async function markInadmissible(court, e, reason) {
    await Chain.send(court, "markInadmissible", [e.id, reason]);
    putIn("transit", String(e.id), undefined);
    UI.toast(`Evidence #${e.id} ruled inadmissible`, "success");
  }

  /** Public verification: read-only calls only, no account or transaction needed. */
  async function verifyFile(file) {
    const c = Chain.contract;
    const fp = {};
    let id256 = 0;
    let id3 = 0;
    let rid = 0;
    const run = await UI.runSteps(document.getElementById("verify-steps"), [
      { title: "Read the file in your browser (nothing is uploaded)", run: async () => `${file.name} · ${fmtBytes(file.bytes.length)}` },
      { title: "SHA-256 of the exact bytes", run: async () => (fp.sha256 = await CC().sha256(file.bytes)) },
      { title: "SHA3-256 of the exact bytes", run: async () => (fp.sha3 = CC().sha3(file.bytes)) },
      {
        title: "Look up both hashes on the blockchain (findByHash, read-only)",
        run: async () => {
          [id256, id3] = (await Promise.all([c.findByHash(fp.sha256), c.findByHash(fp.sha3)])).map(Number);
          if (id256 && id256 === id3) return `Both hashes belong to evidence #${id256}`;
          if (id256 || id3) return `Only one of the two hashes matches (evidence #${id256 || id3})`;
          return "Neither hash is registered as evidence";
        },
      },
      {
        title: "Look up the SHA-256 among anchored analysis reports (findReport)",
        run: async () => {
          rid = Number(await c.findReport(fp.sha256));
          return rid ? `This file is an analysis report attached to evidence #${rid}` : "Not an anchored analysis report";
        },
      },
    ]);
    let verdict = "nomatch";
    let evidenceId = null;
    if (run.ok) {
      if (id256 && id256 === id3) [verdict, evidenceId] = ["intact", id256];
      else if (id256 || id3) [verdict, evidenceId] = ["conflict", id256 || id3];
      else if (rid) [verdict, evidenceId] = ["report", rid];
    } else verdict = "error";
    Shell.state.verify = {
      verdict,
      evidenceId,
      items: run.items,
      file: { name: file.name, size: file.bytes.length, origin: file.origin || "Uploaded file", sha256: fp.sha256, sha3: fp.sha3 },
      claimId: file.claimId || null,
      scroll: true,
    };
    return Shell.state.verify;
  }

  /** Tamper Lab: alter a registered file and re-hash it. */
  async function tamper(evidenceId, altId) {
    const data = await load();
    const e = data.ev(evidenceId);
    if (!e) throw userError(`Evidence #${evidenceId} does not exist`);
    const file = storedFile(e);
    if (!file) throw userError("This evidence file is not stored in this browser.");
    const altered = await ES().alter(altId, file);
    const fp = await CC().fingerprint(altered.bytes);
    const image = ES().kindOf(file) === "image";
    const url = (f) => URL.createObjectURL(new Blob([f.bytes], { type: f.type }));
    return {
      evidenceId,
      altId,
      original: { ...file, url: image ? url(file) : null },
      altered: { ...altered, ...fp, url: image ? url(altered) : null },
      detail: altered.detail,
      sha256: CC().compare(e.sha256, fp.sha256),
      sha3: CC().compare(e.sha3, fp.sha3),
    };
  }

  // ------------------------------------------------------------------
  // Evidence Integrity Certificate
  // ------------------------------------------------------------------
  const ACTION_INFO = [
    { label: "Collected", cls: "tl-accent" },
    { label: "Derived evidence registered", cls: "tl-accent" },
    { label: "Hand-over initiated", cls: "tl-warn" },
    { label: "Hand-over cancelled", cls: "" },
    { label: "Hand-over accepted (re-hash matched)", cls: "tl-ok" },
    { label: "Integrity check passed", cls: "tl-ok" },
    { label: "TAMPER ALARM: integrity check failed", cls: "tl-bad" },
    { label: "Analysis report attached", cls: "tl-accent" },
    { label: "Admitted by the court", cls: "tl-ok" },
    { label: "Ruled inadmissible", cls: "tl-bad" },
  ];
  function who(r) {
    switch (r.action) {
      case A.Collected:
        return `by ${Chain.label(r.to)}`;
      case A.Derived:
        return `by ${Chain.label(r.to)}`;
      case A.TransferInitiated:
      case A.TransferCancelled:
      case A.TransferAccepted:
        return `${Chain.label(r.from)} → ${Chain.label(r.to)}`;
      default:
        return `by ${Chain.label(r.from)}`;
    }
  }
  const hasHash = (h) => h && h !== ZERO_HASH;

  function certData(e) {
    const passed = e.log.filter((r) => r.action === A.TransferAccepted || r.action === A.CheckPassed).length;
    const decision = e.log.find((r) => r.action === A.Admitted || r.action === A.Inadmissible);
    const st =
      e.status === STATUS.Admitted
        ? { cls: "ok", text: `ADMITTED by ${Chain.label(decision.from)} on ${UI.fmtTime(decision.time)}` }
        : e.status === STATUS.Inadmissible
        ? { cls: "bad", text: `RULED INADMISSIBLE by ${Chain.label(decision.from)} on ${UI.fmtTime(decision.time)}: ${decision.note}` }
        : { cls: "pending", text: `NOT YET DECIDED · held by ${Chain.label(e.custodian)}` };
    const integrity = `${passed} matching re-hash(es), ${e.failedChecks} failed${e.flagged ? " (TAMPER ALARM ON RECORD)" : " (no tamper alarm)"}${
      e.lastCheckAt ? `. Last check ${UI.fmtTime(e.lastCheckAt)} by ${Chain.label(e.lastCheckBy)}: ${e.lastCheckOk ? "match" : "MISMATCH"}` : ""
    }`;
    const lineage = `${e.parentId ? `Derived from evidence #${e.parentId}` : "Original evidence"}${e.children.length ? `; derived items: ${e.children.map((c) => "#" + c).join(", ")}` : ""}`;
    const reports = e.log.filter((r) => r.action === A.AnalysisReport);
    const collected = e.log[0];
    return { st, integrity, lineage, reports, collected, number: `CERT-${e.case.number}-E${e.id}` };
  }

  function certificateText(e, meta) {
    const d = certData(e);
    const L = [
      "EVIDENCE INTEGRITY CERTIFICATE",
      `CustodyChain (demo system with fictional data - not a legal document)`,
      `Certificate ${d.number} · generated ${UI.fmtTime(meta.now)} (blockchain time)`,
      "",
      `STATUS      : ${d.st.text}`,
      "",
      `Case        : ${e.case.number} - ${e.case.title}`,
      `Evidence    : #${e.id} ${e.fileName} (${fmtBytes(e.size)}, ${e.size} bytes)`,
      `Description : ${e.description || "-"}`,
      `Collected   : ${UI.fmtTime(e.collectedAt)} by ${Chain.label(e.registeredBy)}`,
      `Registered  : ${UI.fmtTime(e.registeredAt)} (block time)`,
      `Lineage     : ${d.lineage}`,
      `SHA-256     : ${e.sha256}`,
      `SHA3-256    : ${e.sha3}`,
      `Custodian   : ${Chain.label(e.custodian)}`,
      `Integrity   : ${d.integrity}`,
      ...d.reports.map((r, i) => `Report ${i + 1}    : ${r.hash} by ${Chain.label(r.from)} - ${r.note}`),
      "",
      "CHAIN OF CUSTODY",
      ...e.log.map(
        (r, i) =>
          `${String(i + 1).padStart(2)}. ${UI.fmtTime(r.time)}  ${ACTION_INFO[r.action].label} - ${who(r)}${r.note ? ` - "${r.note}"` : ""}${hasHash(r.hash) ? ` [${r.hash}]` : ""}`
      ),
      "",
      `Blockchain  : EvidenceRegistry contract ${meta.contract} on chain ID ${meta.chainId}, block #${meta.block}.`,
      "To verify   : compute the SHA-256 and SHA3-256 of the file and compare them with the values above,",
      '              or drop the file on the "Verify Evidence" page (read-only, no account needed).',
    ];
    return L.join("\n") + "\n";
  }

  function certificateBody(e, meta) {
    const d = certData(e);
    const row = (k, v) => `<tr><th>${k}</th><td>${v}</td></tr>`;
    return `<div class="cert">
      <div class="cert-head">
        <div class="cert-kicker">CustodyChain · demo system with fictional data · not a legal document</div>
        <h2>Evidence Integrity Certificate</h2>
        <div class="cert-no">${esc(d.number)} · generated ${UI.fmtTime(meta.now)} (blockchain time)</div>
      </div>
      <div class="cert-status cert-${d.st.cls}" id="cert-status">${esc(d.st.text)}</div>
      <table class="cert-table">
        ${row("Case", `${esc(e.case.number)} · ${esc(e.case.title)}`)}
        ${row("Evidence", `#${e.id} ${esc(e.fileName)} (${fmtBytes(e.size)})`)}
        ${row("Description", esc(e.description || "-"))}
        ${row("Collected", `${UI.fmtTime(e.collectedAt)} by ${esc(Chain.label(e.registeredBy))}`)}
        ${row("Registered", `${UI.fmtTime(e.registeredAt)} (block time)`)}
        ${row("Lineage", esc(d.lineage))}
        ${row("SHA-256", `<code>${e.sha256}</code>`)}
        ${row("SHA3-256", `<code>${e.sha3}</code>`)}
        ${row("Custodian", esc(Chain.label(e.custodian)))}
        ${row("Integrity", esc(d.integrity))}
        ${d.reports.map((r, i) => row(`Report ${i + 1}`, `<code>${UI.short(r.hash, 10)}</code> by ${esc(Chain.label(r.from))}: ${esc(r.note)}`)).join("")}
      </table>
      <h3>Chain of custody</h3>
      <div class="cert-log-wrap"><table class="cert-table cert-log">
        <thead><tr><th>#</th><th>Time</th><th>Event</th><th>Details</th></tr></thead>
        <tbody>${e.log
          .map(
            (r, i) => `<tr class="${ACTION_INFO[r.action].cls}"><td>${i + 1}</td><td class="nowrap">${UI.fmtTime(r.time)}</td><td>${esc(ACTION_INFO[r.action].label)}</td>
            <td>${esc(who(r))}${r.note ? `<div class="cert-note">“${esc(r.note)}”</div>` : ""}${hasHash(r.hash) ? `<code>${UI.short(r.hash, 10)}</code>` : ""}</td></tr>`
          )
          .join("")}</tbody>
      </table></div>
      <p class="cert-foot">Blockchain record: EvidenceRegistry contract <code>${esc(meta.contract)}</code> on chain ID ${meta.chainId}, block #${meta.block}.
        To verify, compute the SHA-256 and SHA3-256 of the file and compare them with the values above, or drop the file on the
        “Verify Evidence” page (read-only, no account needed). Changing any custody record would change the hash of its block and break the link to every later block.</p>
    </div>`;
  }

  function certificateHtml(e, meta) {
    return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Evidence Integrity Certificate - ${esc(e.case.number)} #${e.id}</title>
<style>
  body { font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; color: #111; background: #fff; margin: 24px; }
  .cert { max-width: 900px; margin: 0 auto; }
  .cert-head { border-bottom: 3px double #1d4ed8; padding-bottom: 10px; margin-bottom: 12px; }
  .cert-kicker { font-size: 12px; color: #555; text-transform: uppercase; letter-spacing: .05em; }
  h2 { margin: 4px 0; font-size: 24px; } h3 { margin: 18px 0 6px; }
  .cert-no { color: #555; font-size: 13px; }
  .cert-status { padding: 10px 12px; border-radius: 8px; font-weight: 700; margin: 10px 0 14px; border: 1px solid #ccc; }
  .cert-ok { background: #e6f5ec; color: #0f5d2e; border-color: #9fd3b2; }
  .cert-bad { background: #fdecea; color: #8f1d14; border-color: #f0a9a2; }
  .cert-pending { background: #fdf2e1; color: #7a4300; border-color: #f0cf98; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; vertical-align: top; padding: 6px 8px; border-bottom: 1px solid #ddd; }
  th { width: 150px; color: #444; font-weight: 600; }
  .cert-log th { width: auto; }
  code { font: 12px ui-monospace, Consolas, monospace; word-break: break-all; }
  .cert-note { color: #444; } .nowrap { white-space: nowrap; }
  tr.tl-bad td { color: #8f1d14; } .cert-foot { color: #444; font-size: 12px; margin-top: 14px; }
</style></head><body>
${certificateBody(e, meta)}
</body></html>
`;
  }

  // ------------------------------------------------------------------
  // View helpers
  // ------------------------------------------------------------------
  const pageHead = (title, sub, actions = "") =>
    `<div class="page-head"><div><h1>${title}</h1><p>${sub}</p></div><div class="row">${actions}</div></div>`;

  function pickMember(state, key, list) {
    state[key] = state[key] && list.some((m) => sameAddr(m.address, state[key])) ? state[key] : list[0].address;
    return list.find((m) => sameAddr(m.address, state[key]));
  }
  const tabs = (list, me, attr) =>
    list.length > 1
      ? `<div class="segmented" style="margin-bottom:16px" role="tablist" aria-label="Acting as">${list
          .map((m) => `<button type="button" role="tab" data-${attr}="${m.address}" class="${sameAddr(m.address, me.address) ? "active" : ""}">${esc(m.name)}</button>`)
          .join("")}</div>`
      : "";
  function bindTabs(el, attr, state, key) {
    el.querySelectorAll(`[data-${attr}]`).forEach((b) =>
      b.addEventListener("click", () => {
        state[key] = b.getAttribute(`data-${attr}`);
        Shell.render();
      })
    );
  }

  function memberCard(me, data, extra = "") {
    const held = data.evidence.filter((e) => sameAddr(e.custodian, me.address) && e.status === STATUS.InCustody).length;
    const incoming = data.evidence.filter((e) => sameAddr(e.pendingTo, me.address)).length;
    return `<div class="card" style="margin-bottom:16px">
      <div class="kv"><span>Acting as</span><strong>${esc(me.name)}</strong> <span class="chip">${ROLE_LABEL[me.role]}</span> ${activeChip(me)}</div>
      <div class="kv"><span>Account</span><code>${esc(me.address)}</code></div>
      <div class="kv"><span>Custody</span><span>${held} item(s) held · ${incoming} incoming hand-over(s)</span></div>
      ${extra}
    </div>`;
  }

  function thumbHtml(e, cls = "thumb") {
    const t = thumbs()[e.sha256];
    if (t) return `<img class="${cls}" src="${t}" alt="Thumbnail of ${esc(e.fileName)}">`;
    const ext = ((/\.([A-Za-z0-9]{1,4})$/.exec(e.fileName) || [])[1] || "file").toUpperCase();
    return `<span class="${cls} thumb-ext" aria-hidden="true">${esc(ext)}</span>`;
  }
  const evTitle = (e) =>
    `<strong>#${e.id} ${esc(e.fileName)}</strong><div class="muted small">${esc(e.case ? e.case.number : "")} · ${fmtBytes(e.size)}${
      e.parentId ? ` · derived from #${e.parentId}` : ""
    }</div>`;

  function evidenceTable(list, { actions = null, empty = "No evidence yet.", compact = false } = {}) {
    if (!list.length) return `<div class="empty">${empty}</div>`;
    if (compact)
      return `<div class="table-wrap"><table class="table">
      <thead><tr><th>Evidence</th><th>Custody</th></tr></thead>
      <tbody>${list
        .map(
          (e) => `<tr>
          <td data-label="Evidence"><div class="ev-cell">${thumbHtml(e)}<div>${evTitle(e)}</div></div></td>
          <td data-label="Custody"><div class="small">${esc(Chain.label(e.custodian))}${e.pendingTo ? ` → ${esc(Chain.label(e.pendingTo))}` : ""}</div>${chips(e)}</td>
        </tr>`
        )
        .join("")}</tbody></table></div>`;
    return `<div class="table-wrap"><table class="table">
      <thead><tr><th>Evidence</th><th>Custodian</th><th>Status</th><th>SHA-256 / SHA3-256</th>${actions ? "<th></th>" : ""}</tr></thead>
      <tbody>${list
        .map(
          (e) => `<tr>
          <td data-label="Evidence"><div class="ev-cell">${thumbHtml(e)}<div>${evTitle(e)}</div></div></td>
          <td data-label="Custodian">${esc(Chain.label(e.custodian))}${e.pendingTo ? `<div class="muted small">→ ${esc(Chain.label(e.pendingTo))}</div>` : ""}</td>
          <td data-label="Status">${chips(e)}</td>
          <td data-label="Hashes"><code>${UI.short(e.sha256, 5)}</code><br><code>${UI.short(e.sha3, 5)}</code></td>
          ${actions ? `<td data-label="Actions">${actions(e)}</td>` : ""}
        </tr>`
        )
        .join("")}</tbody></table></div>`;
  }

  function workCard(me, state, hint) {
    const w = state.work && sameAddr(state.work.member, me.address) ? state.work : null;
    return `<div class="card" id="work-card">
      <div class="card-head"><h2 id="work-title">${w ? esc(w.title) : "Activity"}</h2></div>
      <div id="work-steps">${w ? UI.checklist(w.items) : `<p class="muted">${hint}</p>`}</div>
    </div>`;
  }
  function scrollToWork(el, state) {
    if (state.work && state.work.scroll) {
      state.work.scroll = false;
      if (matchMedia("(max-width: 860px)").matches) {
        const c = el.querySelector("#work-card");
        if (c) setTimeout(() => c.scrollIntoView({ block: "start" }), 0);
      }
    }
  }

  /** Incoming hand-overs for `me`, with accept (re-hash), upload-and-accept and refuse. */
  function incomingCard(me, data) {
    const list = data.evidence.filter((e) => sameAddr(e.pendingTo, me.address));
    return `<div class="card" id="incoming-card">
      <div class="card-head"><h2>Incoming hand-overs</h2><span class="muted small">Accept = re-hash your copy; the contract checks it.</span></div>
      ${
        list.length
          ? `<div class="stack" style="gap:10px">${list
              .map((e) => {
                const copy = deliveredCopy(e);
                return `<div class="item">
                  <div class="item-head">${thumbHtml(e)}<div class="item-title">${evTitle(e)}</div></div>
                  <div class="kv"><span>From</span><span>${esc(Chain.label(e.custodian))} · ${UI.fmtTime(e.pendingSince)}</span></div>
                  <div class="kv"><span>Purpose</span><span>${esc(e.pendingPurpose)}</span></div>
                  <div class="kv"><span>Copy received</span>${
                    copy ? `<span>${esc(copy.name)} · ${fmtBytes(copy.bytes.length)}</span>` : `<span class="chip chip-warn">Not in this browser: upload it</span>`
                  }</div>
                  <div class="row" style="margin-top:8px">
                    <button class="btn btn-sm" data-accept="${e.id}">${icon("check")} Re-hash &amp; accept</button>
                    <label class="btn btn-secondary btn-sm">${icon("upload")} Upload received file<input type="file" data-accept-file="${e.id}" hidden></label>
                    <button class="btn btn-ghost btn-sm" data-refuse="${e.id}">Refuse</button>
                  </div>
                </div>`;
              })
              .join("")}</div>`
          : `<p class="muted small">Nothing is on its way to ${esc(me.name)}.</p>`
      }
    </div>`;
  }

  /** Hand-over form + pending outgoing hand-overs. */
  function transferCard(me, data) {
    const mine = data.evidence.filter((e) => sameAddr(e.custodian, me.address) && e.status === STATUS.InCustody);
    const ready = mine.filter((e) => !e.pendingTo);
    const outgoing = mine.filter((e) => e.pendingTo);
    const recipients = data.members.filter((m) => m.active && !sameAddr(m.address, me.address));
    const preferred = recipients.find((m) => m.role === (me.role === ROLE.Investigator ? ROLE.Analyst : ROLE.Court)) || recipients[0];
    return `<form class="card" id="tr-form" autocomplete="off">
      <div class="card-head"><h2>Hand over evidence</h2><span class="muted small">Step 1 of 2: the receiver must accept with a re-hash.</span></div>
      ${
        ready.length && recipients.length
          ? `<div class="field"><label for="tr-ev">Evidence</label><select id="tr-ev">${ready
              .map((e) => `<option value="${e.id}">#${e.id} ${esc(e.fileName)}</option>`)
              .join("")}</select></div>
            <div class="field"><label for="tr-to">Receiver</label><select id="tr-to">${recipients
              .map((m) => `<option value="${m.address}" data-role="${m.role}" ${preferred && sameAddr(m.address, preferred.address) ? "selected" : ""}>${esc(m.name)} (${ROLE_LABEL[m.role]})</option>`)
              .join("")}</select></div>
            <div class="field"><label for="tr-purpose">Purpose</label><input id="tr-purpose" type="text" maxlength="120" required value="${esc(purposeFor(preferred && preferred.role))}"></div>
            <button class="btn" type="submit" id="tr-btn">${icon("forward")} Start hand-over</button>`
          : `<p class="muted small">${mine.length ? "All items held are already on their way." : `${esc(me.name)} holds no evidence that can be handed over.`}</p>`
      }
      ${
        outgoing.length
          ? `<h3 style="margin:14px 0 6px">Waiting for the receiver</h3>${outgoing
              .map(
                (e) => `<div class="row out-row"><span class="small"><strong>#${e.id}</strong> ${esc(e.fileName)} → ${esc(Chain.label(e.pendingTo))}</span>
                  <button type="button" class="btn btn-ghost btn-sm" data-cancel="${e.id}">Cancel</button></div>`
              )
              .join("")}`
          : ""
      }
    </form>`;
  }
  const purposeFor = (role) =>
    role === ROLE.Analyst ? "Forensic examination and report" : role === ROLE.Court ? "Submission to the court for trial" : "Return to the investigating officer";

  function bindCustody(el, me, data, action) {
    const form = el.querySelector("#tr-form");
    const to = el.querySelector("#tr-to");
    if (to)
      to.addEventListener("change", () => {
        el.querySelector("#tr-purpose").value = purposeFor(Number(to.selectedOptions[0].dataset.role));
      });
    if (form && el.querySelector("#tr-btn"))
      form.addEventListener("submit", (ev) => {
        ev.preventDefault();
        action(el.querySelector("#tr-btn"), () =>
          initiateTransfer(me.address, Number(form.querySelector("#tr-ev").value), to.value, form.querySelector("#tr-purpose").value.trim())
        );
      });
    el.querySelectorAll("[data-cancel]").forEach((b) => b.addEventListener("click", () => action(b, () => cancelTransfer(me.address, data.ev(b.dataset.cancel)))));
    el.querySelectorAll("[data-refuse]").forEach((b) => b.addEventListener("click", () => action(b, () => cancelTransfer(me.address, data.ev(b.dataset.refuse)))));
    el.querySelectorAll("[data-accept]").forEach((b) => b.addEventListener("click", () => action(b, () => acceptTransfer(me.address, data.ev(b.dataset.accept)))));
    el.querySelectorAll("[data-accept-file]").forEach((inp) =>
      inp.addEventListener("change", async () => {
        const f = await readInput(inp);
        if (f) action(inp.closest("label"), () => acceptTransfer(me.address, data.ev(inp.dataset.acceptFile), f));
      })
    );
  }

  function timelineHtml(e) {
    return `<ol class="timeline" id="timeline">${e.log
      .map(
        (r) => `<li class="${ACTION_INFO[r.action].cls}">
          <div class="tl-head"><strong>${esc(ACTION_INFO[r.action].label)}</strong><span class="muted small nowrap">${UI.fmtTime(r.time)}</span></div>
          <div class="small">${esc(who(r))}</div>
          ${r.note ? `<div class="small muted">“${esc(r.note)}”</div>` : ""}
          ${hasHash(r.hash) ? `<code class="tl-hash">${UI.short(r.hash, 10)}</code>` : ""}
        </li>`
      )
      .join("")}</ol>`;
  }

  function lineageHtml(e, data) {
    const parts = [];
    if (e.parentId) parts.push(`Derived from <strong>#${e.parentId}</strong> ${esc(data.ev(e.parentId).fileName)}`);
    if (e.children.length) parts.push(`Derived items: ${e.children.map((c) => `<strong>#${c}</strong> ${esc(data.ev(c).fileName)}`).join(", ")}`);
    return parts.length ? `<div class="kv"><span>Lineage</span><span>${parts.join("<br>")}</span></div>` : "";
  }

  function factsHtml(e, data) {
    return `<dl class="facts">
      <dt>Case</dt><dd>${esc(e.case.number)} · ${esc(e.case.title)}</dd>
      <dt>File</dt><dd>${esc(e.fileName)} · ${fmtBytes(e.size)}</dd>
      <dt>Description</dt><dd>${esc(e.description || "-")}</dd>
      <dt>Collected</dt><dd>${UI.fmtTime(e.collectedAt)} by ${esc(Chain.label(e.registeredBy))}</dd>
      <dt>Custodian</dt><dd>${esc(Chain.label(e.custodian))}${e.pendingTo ? ` (hand-over to ${esc(Chain.label(e.pendingTo))} pending)` : ""}</dd>
      <dt>SHA-256</dt><dd><code>${e.sha256}</code></dd>
      <dt>SHA3-256</dt><dd><code>${e.sha3}</code></dd>
      ${e.parentId ? `<dt>Derived from</dt><dd>#${e.parentId} ${esc(data.ev(e.parentId).fileName)}</dd>` : ""}
      ${e.children.length ? `<dt>Derived items</dt><dd>${e.children.map((c) => `#${c} ${esc(data.ev(c).fileName)}`).join(", ")}</dd>` : ""}
    </dl>`;
  }

  // ------------------------------------------------------------------
  // Views
  // ------------------------------------------------------------------
  async function viewHome(el, { data, action }) {
    const ev = data.evidence;
    const handovers = ev.reduce((n, e) => n + e.log.filter((r) => r.action === A.TransferAccepted).length, 0);
    el.innerHTML = `
      ${pageHead(
        "Digital Evidence Integrity",
        "CCTV stills, server logs and chat exports are easy to alter, swap or dispute in court, and paper chain-of-custody registers are easy to fake or lose. CustodyChain records the SHA-256 and SHA3-256 fingerprints of every file on a blockchain shared by the police, the forensic lab and the court, and custody only moves when the receiver proves, by re-hashing, that its copy is intact.",
        `<button class="btn" id="demo-btn">${icon("layers")} Load sample case</button>
         <a class="btn btn-secondary" href="#/verify">${icon("search")} Verify a file</a>`
      )}
      <div class="grid-4" style="margin-bottom:16px">
        <div class="card stat"><span class="stat-value">${ev.length}</span><span class="stat-label">Evidence items on-chain (${data.cases.length} case${data.cases.length === 1 ? "" : "s"})</span></div>
        <div class="card stat"><span class="stat-value">${handovers}</span><span class="stat-label">Hand-overs verified by re-hash</span></div>
        <div class="card stat"><span class="stat-value">${ev.filter((e) => e.flagged).length}</span><span class="stat-label">Tamper alarms raised</span></div>
        <div class="card stat"><span class="stat-value">${ev.filter((e) => e.status === STATUS.Admitted).length}</span><span class="stat-label">Admitted by the court</span></div>
      </div>
      <div class="card" style="margin-bottom:16px">
        <div class="card-head"><h2>How it works</h2></div>
        <div class="flow" style="--steps:4">
          <div class="flow-step"><h3>Collect &amp; fingerprint</h3><p>The investigator's browser computes SHA-256 and SHA3-256 of the file. Only the hashes go on-chain; the file stays off-chain.</p></div>
          <div class="flow-step"><h3>Two-step hand-over</h3><p>The custodian starts a transfer. The receiver re-hashes its copy and the smart contract accepts only a matching hash.</p></div>
          <div class="flow-step"><h3>Analyse &amp; derive</h3><p>The forensic lab anchors the hash of its report and registers derived files (extracts, enhanced crops) linked to the original.</p></div>
          <div class="flow-step"><h3>Verify &amp; admit</h3><p>The court admits only evidence it verified itself with no tamper alarm. Anyone can check a file and see its custody timeline.</p></div>
        </div>
      </div>
      <div class="grid-2" style="align-items:start">
        <div class="card"><div class="card-head"><h2>Evidence register</h2><a href="#/investigator" class="small">Register evidence</a></div>
          ${evidenceTable(ev.slice().reverse().slice(0, 8), { compact: true, empty: "No evidence yet. Click <strong>Load sample case</strong> or open the Investigator page." })}</div>
        <div class="card">
          <div class="card-head"><h2>Demo script (5 minutes)</h2></div>
          <ol class="demo-list">
            <li><a href="#/investigator">Investigator</a>: open case CC-2026-0147 and register the sample server log. Watch read → SHA-256 → SHA3-256 → transaction. Register it again: blocked as a duplicate.</li>
            <li>Register the CCTV still (as City Police Station 7) and the chat export. Hand the log over to the Regional Forensic Science Lab.</li>
            <li><a href="#/lab">Forensic Lab</a>: re-hash &amp; accept the log, anchor the analysis report, register the derived extract, hand the log to the court.</li>
            <li>Hand the CCTV still to the lab. In the <a href="#/tamper">Tamper Lab</a> edit one pixel: both hashes change completely. Swap the edited copy into the delivery: the lab's acceptance is blocked and a tamper alarm is recorded.</li>
            <li><a href="#/court">Court</a>: accept the log, admit it and print the Evidence Integrity Certificate. Rule the CCTV still inadmissible.</li>
            <li><a href="#/verify">Verify Evidence</a>: as the defence, check the log file: match, with the full custody timeline.</li>
            <li><a href="#/explorer">Blockchain Explorer</a>: hash-linked blocks and the audit log. <a href="#/admin">State Forensic Authority</a>: suspend a member.</li>
          </ol>
        </div>
      </div>`;
    const db = el.querySelector("#demo-btn");
    db.addEventListener("click", () => action(db, loadDemoCase));
  }

  async function viewInvestigator(el, { data, state, action, go }) {
    if (!data.investigators.length) return (el.innerHTML = `<div class="empty">No investigators registered.</div>`);
    const me = pickMember(state, "inv", data.investigators);
    const reg = (state.reg = state.reg || {});
    if (!data.cases.some((c) => c.id === reg.caseId)) reg.caseId = data.cases.length ? data.cases[data.cases.length - 1].id : null;
    const kase = data.kase(reg.caseId);
    const used = samplesUsed();
    const key = `${me.address}|${reg.caseId}`;
    if (reg.key !== key) {
      reg.key = key;
      const pref = /station/i.test(me.name) ? ["cctv", "log", "chat"] : ["log", "chat", "cctv"];
      reg.source = (kase && pref.find((k) => !used[`${kase.id}:${k}`])) || (kase ? "upload" : pref[0]);
      reg.upload = null;
    }
    const sample = ES().SAMPLES.find((s) => s.id === reg.source);
    const ago = { log: 5400, cctv: 7200, chat: 3600 }[reg.source] || 3600;
    const numbers = new Set(data.cases.map((c) => c.number));
    const idea = CASE_IDEAS.find(([n]) => !numbers.has(n)) || [`CC-2026-0${160 + data.cases.length}`, "New case"];
    const mine = data.evidence.filter((e) => sameAddr(e.custodian, me.address));

    el.innerHTML = `
      ${pageHead("Investigator", "Police units open cases, register the digital evidence they seize and hand it over. Both fingerprints are computed in the browser; the file itself never goes on-chain.")}
      ${tabs(data.investigators, me, "inv")}
      ${memberCard(me, data)}
      <div class="grid-2" style="align-items:start;margin-bottom:16px">
        <form class="card" id="reg-form" autocomplete="off">
          <div class="card-head"><h2>Register evidence</h2></div>
          ${
            kase
              ? `<div class="grid-2" style="gap:12px">
                  <div class="field"><label for="f-case">Case</label><select id="f-case">${data.cases
                    .map((c) => `<option value="${c.id}" ${c.id === kase.id ? "selected" : ""}>${esc(c.number)} · ${esc(c.title)}</option>`)
                    .join("")}</select></div>
                  <div class="field"><label for="f-source">File</label><select id="f-source">${ES()
                    .SAMPLES.map((s) => `<option value="${s.id}" ${s.id === reg.source ? "selected" : ""}>${esc(s.label)}${used[`${kase.id}:${s.id}`] ? " (registered)" : ""}</option>`)
                    .join("")}<option value="upload" ${reg.source === "upload" ? "selected" : ""}>Upload your own file…</option></select></div>
                </div>
                ${
                  reg.source === "upload"
                    ? `<div class="field"><label for="f-file">Evidence file (max 10 MB)</label><input id="f-file" type="file">
                        <span class="hint">Hashed in your browser. Files up to 512 KB are also kept in this browser's evidence locker; larger ones only by their hashes.</span></div>`
                    : `<p class="muted small" style="margin-top:-4px">${esc(sample.hint)} Generated in your browser, fictional data.</p>`
                }
                <figure class="preview" id="reg-preview"><div class="preview-empty">${reg.source === "upload" ? "Choose a file" : "Generating the sample…"}</div></figure>
                <div class="field"><label for="f-desc">Description (stored on-chain)</label><input id="f-desc" type="text" maxlength="200" value="${esc(sample ? sample.description : "")}"></div>
                <div class="field"><label for="f-collected">Collected at</label><input id="f-collected" type="datetime-local" required value="${toLocalInput(Chain.now() - ago)}">
                  <span class="hint">The contract rejects collection times later than the current block time.</span></div>
                <button class="btn" type="submit" id="reg-btn">${icon("shield")} Hash &amp; register on the blockchain</button>`
              : `<p class="muted">Open a case first (form on the right).</p>`
          }
        </form>
        <div class="stack">
          ${workCard(me, state, "The steps run in your browser and appear here: reading the file, SHA-256, SHA3-256, the blockchain transaction and the off-chain copy.")}
          <form class="card" id="case-form" autocomplete="off">
            <div class="card-head"><h2>Open a case</h2></div>
            <div class="grid-2" style="gap:12px">
              <div class="field"><label for="f-casenum">Case number</label><input id="f-casenum" type="text" required maxlength="40" value="${esc(idea[0])}"></div>
              <div class="field"><label for="f-casetitle">Title</label><input id="f-casetitle" type="text" required maxlength="120" value="${esc(idea[1])}"></div>
            </div>
            <button class="btn btn-secondary" type="submit" id="case-btn">${icon("book")} Open case on-chain</button>
          </form>
        </div>
      </div>
      <div class="grid-2" style="align-items:start;margin-bottom:16px">
        ${transferCard(me, data)}
        ${incomingCard(me, data)}
      </div>
      <div class="card" style="margin-bottom:16px">
        <div class="card-head"><h2>Evidence held by ${esc(me.name)}</h2></div>
        ${evidenceTable(mine, {
          empty: "No evidence held.",
          actions: (e) => `<button class="btn btn-secondary btn-sm" data-verify="${e.id}">${icon("search")} Timeline</button>`,
        })}
      </div>
      <div class="card">
        <div class="card-head"><h2>Cases</h2></div>
        ${
          data.cases.length
            ? `<div class="table-wrap"><table class="table"><thead><tr><th>Case</th><th>Opened by</th><th>Evidence</th></tr></thead><tbody>${data.cases
                .map(
                  (c) => `<tr><td data-label="Case"><strong>${esc(c.number)}</strong><div class="muted small">${esc(c.title)}</div></td>
                  <td data-label="Opened by">${esc(Chain.label(c.createdBy))}<div class="muted small">${UI.fmtTime(c.createdAt)}</div></td>
                  <td data-label="Evidence">${c.evidenceIds.length ? c.evidenceIds.map((i) => "#" + i).join(", ") : "-"}</td></tr>`
                )
                .join("")}</tbody></table></div>`
            : `<div class="empty">No cases yet.</div>`
        }
      </div>`;

    bindTabs(el, "inv", state, "inv");
    bindCustody(el, me, data, action);
    scrollToWork(el, state);
    el.querySelectorAll("[data-verify]").forEach((b) =>
      b.addEventListener("click", () => {
        state.verify = { verdict: "lookup", evidenceId: Number(b.dataset.verify), items: [] };
        go("verify");
      })
    );
    const caseForm = el.querySelector("#case-form");
    caseForm.addEventListener("submit", (ev) => {
      ev.preventDefault();
      action(el.querySelector("#case-btn"), async () => {
        reg.caseId = await createCase(me.address, caseForm.querySelector("#f-casenum").value.trim(), caseForm.querySelector("#f-casetitle").value.trim());
      });
    });
    if (!kase) return;

    const preview = el.querySelector("#reg-preview");
    const currentFile = () => (reg.source === "upload" ? Promise.resolve(reg.upload) : sampleFile(reg.source, kase));
    const showPreview = (file) => {
      if (!preview.isConnected || !file) return;
      const kind = ES().kindOf(file);
      let body;
      if (kind === "image") body = `<img src="${URL.createObjectURL(new Blob([file.bytes], { type: file.type }))}" alt="Evidence preview">`;
      else if (kind === "text") body = `<pre class="excerpt">${esc(new TextDecoder().decode(file.bytes.slice(0, 2400)).split("\n").slice(0, 12).join("\n"))}</pre>`;
      else body = `<pre class="excerpt">${esc(UI.bytesToHex(file.bytes.slice(0, 48)))}…</pre>`;
      preview.innerHTML = `${body}<figcaption>${esc(file.name)} · ${fmtBytes(file.bytes.length)}</figcaption>`;
    };
    currentFile().then(showPreview).catch((e) => UI.toast(e.message, "error"));
    el.querySelector("#f-case").addEventListener("change", (e) => {
      reg.caseId = Number(e.target.value);
      Shell.render();
    });
    el.querySelector("#f-source").addEventListener("change", (e) => {
      reg.source = e.target.value;
      reg.upload = null;
      Shell.render();
    });
    const fileIn = el.querySelector("#f-file");
    if (fileIn)
      fileIn.addEventListener("change", async () => {
        const f = await readInput(fileIn);
        if (!f) return;
        reg.upload = f;
        showPreview(f);
      });
    const form = el.querySelector("#reg-form");
    form.addEventListener("submit", (ev) => {
      ev.preventDefault();
      action(el.querySelector("#reg-btn"), async () => {
        const file = await currentFile();
        if (!file) return UI.toast("Choose a file first", "error");
        const collectedAt = fromLocalInput(form.querySelector("#f-collected").value);
        if (!collectedAt) return UI.toast("Enter the collection time", "error");
        await registerEvidence(me.address, file, { caseId: kase.id, description: form.querySelector("#f-desc").value.trim(), collectedAt });
        reg.key = null; // suggest the next sample
      });
    });
  }

  async function viewLab(el, { data, state, action }) {
    if (!data.analysts.length) return (el.innerHTML = `<div class="empty">No forensic labs registered.</div>`);
    const me = pickMember(state, "lab", data.analysts);
    const held = data.evidence.filter((e) => sameAddr(e.custodian, me.address));
    const R = reportStore();
    const F = files();

    el.innerHTML = `
      ${pageHead("Forensic Lab", "The lab accepts evidence only after re-hashing the copy it received, then examines it, anchors the hash of its analysis report and registers derived evidence (extracts, enhanced crops) linked to the original.")}
      ${tabs(data.analysts, me, "lab")}
      ${memberCard(me, data)}
      <div class="grid-2" style="align-items:start;margin-bottom:16px">
        <div class="stack">${incomingCard(me, data)}${transferCard(me, data)}</div>
        ${workCard(me, state, "Accepting, examining and registering run step by step here.")}
      </div>
      <div class="card">
        <div class="card-head"><h2>Evidence under examination</h2><span class="muted small">Reports and derived files are linked to the original on-chain.</span></div>
        ${
          held.length
            ? `<div class="stack" style="gap:10px">${held
                .map((e) => {
                  const reports = e.log.filter((r) => r.action === A.AnalysisReport);
                  const open = e.status === STATUS.InCustody;
                  return `<div class="item">
                    <div class="item-head">${thumbHtml(e)}<div class="item-title">${evTitle(e)}</div>${chips(e)}</div>
                    <div class="kv"><span>SHA-256</span><code>${UI.short(e.sha256, 10)}</code></div>
                    <div class="kv"><span>SHA3-256</span><code>${UI.short(e.sha3, 10)}</code></div>
                    ${reports
                      .map(
                        (r) => `<div class="kv"><span>Report</span><span>${esc(r.note)} <code>${UI.short(r.hash, 4)}</code>
                        ${R[r.hash] ? `<button type="button" class="btn btn-ghost btn-sm" data-dl-report="${r.hash}">Download</button>` : ""}</span></div>`
                      )
                      .join("")}
                    ${
                      open
                        ? `<div class="row" style="margin-top:8px">
                            <button class="btn btn-sm" data-report="${e.id}" ${F[e.sha256] ? "" : "disabled title='The file is not in this browser'"}>${icon("book")} Examine &amp; anchor report</button>
                            <label class="btn btn-secondary btn-sm">${icon("upload")} Upload own report<input type="file" data-report-file="${e.id}" hidden></label>
                            ${e.parentId === 0 && F[e.sha256] ? `<button class="btn btn-secondary btn-sm" data-derive="${e.id}">${icon("layers")} Register derived extract</button>` : ""}
                            <label class="btn btn-secondary btn-sm">${icon("upload")} Upload derived file<input type="file" data-derive-file="${e.id}" hidden></label>
                            <button class="btn btn-ghost btn-sm" data-check="${e.id}">${icon("check")} Re-verify</button>
                          </div>`
                        : ""
                    }
                  </div>`;
                })
                .join("")}</div>`
            : `<div class="empty">${esc(me.name)} holds no evidence. Accept an incoming hand-over first.</div>`
        }
      </div>`;

    bindTabs(el, "lab", state, "lab");
    bindCustody(el, me, data, action);
    scrollToWork(el, state);
    el.querySelectorAll("[data-report]").forEach((b) => b.addEventListener("click", () => action(b, () => addReport(me.address, data.ev(b.dataset.report)))));
    el.querySelectorAll("[data-derive]").forEach((b) => b.addEventListener("click", () => action(b, () => deriveEvidence(me.address, data.ev(b.dataset.derive)))));
    el.querySelectorAll("[data-check]").forEach((b) => b.addEventListener("click", () => action(b, () => verifyIntegrity(me.address, data.ev(b.dataset.check)))));
    el.querySelectorAll("[data-report-file]").forEach((inp) =>
      inp.addEventListener("change", async () => {
        const f = await readInput(inp);
        if (!f) return;
        const summary = prompt("One-line summary of the report (stored on-chain):", `Report ${f.name}`);
        if (summary) action(inp.closest("label"), () => addReport(me.address, data.ev(inp.dataset.reportFile), { ...f, summary }));
      })
    );
    el.querySelectorAll("[data-derive-file]").forEach((inp) =>
      inp.addEventListener("change", async () => {
        const f = await readInput(inp);
        if (!f) return;
        const description = prompt("Describe the derived file (stored on-chain):", `Derived from evidence #${inp.dataset.deriveFile}`);
        if (description) action(inp.closest("label"), () => deriveEvidence(me.address, data.ev(inp.dataset.deriveFile), { ...f, description }));
      })
    );
    el.querySelectorAll("[data-dl-report]").forEach((b) =>
      b.addEventListener("click", () => {
        const r = R[b.dataset.dlReport];
        UI.download(r.name, new Blob([UI.base64ToBytes(r.b64)], { type: r.type }));
      })
    );
  }

  async function viewCourt(el, { data, state, action }) {
    if (!data.courts.length) return (el.innerHTML = `<div class="empty">No courts registered.</div>`);
    const me = pickMember(state, "court", data.courts);
    const decidedByMe = (e) => e.log.some((r) => (r.action === A.Admitted || r.action === A.Inadmissible) && sameAddr(r.from, me.address));
    const before = data.evidence.filter((e) => sameAddr(e.custodian, me.address) || decidedByMe(e));
    const alarms = data.evidence.filter((e) => e.flagged && e.status === STATUS.InCustody);
    const cert = state.cert ? data.ev(state.cert) : null;
    const meta = cert ? { now: Chain.now(), block: await Chain.provider.getBlockNumber(), contract: Chain.address, chainId: Chain.chainId } : null;

    el.innerHTML = `
      ${pageHead("Court", "The court accepts evidence with a re-hash like everyone else, may re-verify it, and admits it only when no tamper alarm is on record and its own latest check matched. It can issue an Evidence Integrity Certificate for every item.")}
      ${tabs(data.courts, me, "court")}
      ${memberCard(me, data)}
      <div class="grid-2" style="align-items:start;margin-bottom:16px">
        <div class="stack">
          ${incomingCard(me, data)}
          <div class="card" id="alarm-card">
            <div class="card-head"><h2>Tamper alarms</h2><span class="muted small">Items with a failed integrity check on record</span></div>
            ${
              alarms.length
                ? `<div class="stack" style="gap:10px">${alarms
                    .map((e) => {
                      const last = e.log.filter((r) => r.action === A.CheckFailed).slice(-1)[0];
                      return `<div class="item item-bad">
                        <div class="item-head">${thumbHtml(e)}<div class="item-title">${evTitle(e)}</div>${chips(e)}</div>
                        <div class="kv"><span>Failed checks</span><span>${e.failedChecks} · last ${UI.fmtTime(last.time)} by ${esc(Chain.label(last.from))}</span></div>
                        <div class="kv"><span>Note</span><span>${esc(last.note)}</span></div>
                        <div class="row" style="margin-top:8px"><button class="btn btn-danger btn-sm" data-inadmissible="${e.id}">Rule inadmissible</button>
                          <button class="btn btn-ghost btn-sm" data-cert="${e.id}">Certificate</button></div>
                      </div>`;
                    })
                    .join("")}</div>`
                : `<p class="muted small">No tamper alarms.</p>`
            }
          </div>
        </div>
        ${workCard(me, state, "Accepting and re-verifying run step by step here.")}
      </div>
      <div class="card" style="margin-bottom:16px">
        <div class="card-head"><h2>Evidence before ${esc(me.name)}</h2></div>
        ${
          before.length
            ? `<div class="stack" style="gap:10px">${before
                .map((e) => {
                  const open = e.status === STATUS.InCustody && sameAddr(e.custodian, me.address);
                  return `<div class="item">
                    <div class="item-head">${thumbHtml(e)}<div class="item-title">${evTitle(e)}</div>${chips(e)}</div>
                    <div class="kv"><span>Latest check</span><span>${
                      e.lastCheckAt ? `${UI.fmtTime(e.lastCheckAt)} by ${esc(Chain.label(e.lastCheckBy))}: ${e.lastCheckOk ? "match" : "MISMATCH"}` : "-"
                    }</span></div>
                    <div class="kv"><span>Integrity</span><span>${e.failedChecks ? `<strong class="bad-text">${e.failedChecks} failed check(s)</strong>` : "no failed checks"} · ${e.reportCount} analysis report(s)</span></div>
                    <div class="row" style="margin-top:8px">
                      ${
                        open
                          ? `<button class="btn btn-secondary btn-sm" data-check="${e.id}">${icon("check")} Re-verify</button>
                             <button class="btn btn-sm" data-admit="${e.id}">${icon("shield")} Admit</button>
                             <button class="btn btn-danger btn-sm" data-inadmissible="${e.id}">Rule inadmissible</button>`
                          : ""
                      }
                      <button class="btn btn-ghost btn-sm" data-cert="${e.id}">${icon("book")} Certificate</button>
                    </div>
                  </div>`;
                })
                .join("")}</div>`
            : `<div class="empty">No evidence before this court yet. Items arrive through hand-overs.</div>`
        }
      </div>
      ${
        cert
          ? `<section class="card certificate" id="certificate">
              <div class="row cert-actions">
                <button type="button" class="btn btn-sm" id="cert-print">${icon("book")} Print</button>
                <button type="button" class="btn btn-secondary btn-sm" id="cert-txt">Download .txt</button>
                <button type="button" class="btn btn-secondary btn-sm" id="cert-html">Download .html</button>
                <button type="button" class="btn btn-ghost btn-sm" id="cert-close">Close</button>
              </div>
              ${certificateBody(cert, meta)}
            </section>`
          : ""
      }`;

    bindTabs(el, "court", state, "court");
    bindCustody(el, me, data, action);
    scrollToWork(el, state);
    el.querySelectorAll("[data-check]").forEach((b) => b.addEventListener("click", () => action(b, () => verifyIntegrity(me.address, data.ev(b.dataset.check)))));
    el.querySelectorAll("[data-admit]").forEach((b) => b.addEventListener("click", () => action(b, () => admit(me.address, data.ev(b.dataset.admit)))));
    el.querySelectorAll("[data-inadmissible]").forEach((b) =>
      b.addEventListener("click", () => {
        const e = data.ev(b.dataset.inadmissible);
        const reason = prompt(
          "Reason for ruling this evidence inadmissible (stored on-chain):",
          e.flagged ? "Tamper alarm on record: a copy failed the integrity check" : "Chain of custody not established"
        );
        if (reason) action(b, () => markInadmissible(me.address, e, reason.trim()));
      })
    );
    el.querySelectorAll("[data-cert]").forEach((b) =>
      b.addEventListener("click", () => {
        state.cert = Number(b.dataset.cert);
        Shell.render().then(() => {
          const c = document.getElementById("certificate");
          if (c) c.scrollIntoView({ block: "start" });
        });
      })
    );
    if (cert) {
      const base = `certificate-${slug(cert.case.number)}-E${cert.id}`;
      el.querySelector("#cert-print").addEventListener("click", () => window.print());
      el.querySelector("#cert-txt").addEventListener("click", () => UI.download(`${base}.txt`, certificateText(cert, meta)));
      el.querySelector("#cert-html").addEventListener("click", () => UI.download(`${base}.html`, certificateHtml(cert, meta), "text/html"));
      el.querySelector("#cert-close").addEventListener("click", () => {
        state.cert = null;
        Shell.render();
      });
    }
  }

  const VERDICTS = {
    intact: { cls: "verdict-ok", icon: "check", title: "Intact: registered evidence" },
    report: { cls: "verdict-ok", icon: "book", title: "Anchored analysis report" },
    conflict: { cls: "verdict-bad", icon: "bug", title: "Hash conflict: treat as tampered" },
    nomatch: { cls: "verdict-bad", icon: "bug", title: "No match: not registered evidence" },
    error: { cls: "verdict-bad", icon: "bug", title: "Could not verify" },
    lookup: { cls: "verdict-info", icon: "search", title: "Custody record" },
  };

  function hashCompareHtml(label, registered, other) {
    const mask = CC().digitMask(registered, other);
    const bits = CC().bitMask(registered, other);
    const n = CC().compare(registered, other);
    const hex = (h, marks) =>
      h
        .slice(2)
        .split("")
        .map((ch, i) => `${i && i % 8 === 0 ? "<wbr>" : ""}${marks && mask[i] ? `<mark>${ch}</mark>` : ch}`)
        .join("");
    return `<div class="hash-cmp">
      <div class="hash-cmp-head"><strong>${label}</strong>${
        n.digits ? `<span class="chip chip-bad">${n.digits}/64 hex digits · ${n.bits}/256 bits changed</span>` : `<span class="chip chip-ok">identical</span>`
      }</div>
      <div class="hash-line"><span>Registered</span><code class="hex">${hex(registered)}</code></div>
      <div class="hash-line"><span>This copy</span><code class="hex">${hex(other, true)}</code></div>
      <div class="bitgrid" role="img" aria-label="${n.bits} of 256 output bits flipped">${bits.map((v) => `<span class="${v ? "flip" : ""}"></span>`).join("")}</div>
    </div>`;
  }

  function verdictHtml(v, data) {
    const V = VERDICTS[v.verdict];
    const e = v.evidenceId ? data.ev(v.evidenceId) : null;
    let sub = "";
    const notes = [];
    if (v.verdict === "intact")
      sub = `Both SHA-256 and SHA3-256 match evidence <strong>#${e.id}</strong> in case ${esc(e.case.number)}, registered ${UI.fmtTime(e.registeredAt)} by ${esc(
        Chain.label(e.registeredBy)
      )}. This file has not changed by a single bit.`;
    else if (v.verdict === "report") {
      const r = e.log.find((x) => x.action === A.AnalysisReport && x.hash === v.file.sha256);
      sub = `Its SHA-256 was anchored for evidence <strong>#${e.id}</strong> by ${esc(Chain.label(r ? r.from : ""))} on ${r ? UI.fmtTime(r.time) : "-"}: “${esc(r ? r.note : "")}”.`;
    } else if (v.verdict === "conflict") sub = `Only one of the two hashes matches evidence #${e.id}. A real file cannot do that by accident: treat it as tampered.`;
    else if (v.verdict === "nomatch")
      sub = `Neither hash is on the blockchain. If this file is supposed to be a registered item, it has been altered: any change, even one bit, gives completely different hashes.`;
    else if (v.verdict === "error") sub = "A verification step failed (see the steps).";
    else if (v.verdict === "lookup") sub = `Evidence <strong>#${e.id}</strong> ${esc(e.fileName)}, read from the smart contract. No file was checked.`;
    if (e && v.verdict !== "report") {
      if (e.flagged) notes.push(`Tamper alarm on record: ${e.failedChecks} copy/copies failed an integrity check.`);
      if (e.status === STATUS.Admitted) notes.push("Admitted by the court.");
      if (e.status === STATUS.Inadmissible) notes.push(`Ruled inadmissible: “${esc(e.log.find((r) => r.action === A.Inadmissible).note)}”.`);
    }
    return `<div class="verdict ${V.cls}" id="verdict" data-verdict="${v.verdict}">
      <span class="v-icon" aria-hidden="true">${icon(V.icon)}</span>
      <div><div class="v-title">${V.title}</div><div class="v-sub">${sub}</div>${notes.map((n) => `<div class="v-note">${n}</div>`).join("")}</div>
    </div>`;
  }

  async function viewVerify(el, { data, state, action }) {
    const F = files();
    const stored = data.evidence.filter((e) => F[e.sha256]);
    const v = state.verify && (state.verify.evidenceId == null || data.ev(state.verify.evidenceId)) ? state.verify : null;
    const file = state.verifyFile;
    const e = v && v.evidenceId ? data.ev(v.evidenceId) : null;
    const claim = v && v.verdict === "nomatch" && v.claimId ? data.ev(v.claimId) : null;
    const showRecord = e && v.verdict !== "report";

    el.innerHTML = `
      ${pageHead("Verify Evidence", "Public and free, for the defence, journalists or anyone else: no account or transaction. The file is hashed in your browser and looked up on the blockchain with read-only calls; matching evidence shows its full custody timeline.")}
      <div class="grid-2" style="align-items:start">
        <div class="stack">
          <div class="card">
            <div class="card-head"><h2>File to check</h2>
              <label class="btn">${icon("upload")} Choose a file<input type="file" id="verify-file" hidden></label></div>
            ${
              file
                ? `<div class="file-line">${icon("search")}<div><strong>${esc(file.name)}</strong><div class="muted small">${esc(file.origin || "Uploaded file")} · ${fmtBytes(
                    file.bytes.length
                  )}</div></div><button type="button" class="btn btn-secondary btn-sm" id="verify-btn">Check again</button></div>`
                : `<p class="muted small">Any file up to 10 MB. Or pick an evidence file kept in this browser:</p>`
            }
            ${
              stored.length
                ? `<div class="gallery" style="margin-top:12px">${stored
                    .map((x) => `<button type="button" class="gallery-item" data-pick="${x.id}" title="Check the file of evidence #${x.id}">${thumbHtml(x, "gallery-img")}<span>#${x.id} ${esc(x.fileName)}</span></button>`)
                    .join("")}</div>`
                : `<p class="muted small" style="margin-top:8px">None yet. Register evidence on the <a href="#/investigator">Investigator</a> page.</p>`
            }
            ${
              data.evidence.length
                ? `<label for="lookup" class="small muted lookup-label">Or show a custody record without a file:</label>
                  <div class="lookup-row"><select id="lookup">${data.evidence.map((x) => `<option value="${x.id}">#${x.id} ${esc(x.fileName)}</option>`).join("")}</select>
                    <button type="button" class="btn btn-secondary btn-sm" id="lookup-btn">Show</button></div>`
                : ""
            }
          </div>
          <div class="card">
            <div class="card-head"><h2>Verification steps</h2></div>
            <div id="verify-steps">${v && v.items && v.items.length ? UI.checklist(v.items) : `<p class="muted">Choose a file to start.</p>`}</div>
          </div>
        </div>
        <div class="card" id="result-card">
          <div class="card-head"><h2>Result</h2></div>
          ${
            v
              ? `${verdictHtml(v, data)}
                 ${v.file ? `<dl class="facts"><dt>File checked</dt><dd>${esc(v.file.name)} · ${fmtBytes(v.file.size)}</dd><dt>SHA-256</dt><dd><code>${v.file.sha256 || "-"}</code></dd><dt>SHA3-256</dt><dd><code>${v.file.sha3 || "-"}</code></dd></dl>` : ""}
                 ${
                   claim && v.file && v.file.sha256
                     ? `<h3 style="margin:16px 0 8px">Compared with evidence #${claim.id} (${esc(claim.fileName)})</h3>
                        ${hashCompareHtml("SHA-256", claim.sha256, v.file.sha256)}${hashCompareHtml("SHA3-256", claim.sha3, v.file.sha3)}`
                     : ""
                 }
                 ${showRecord ? `<h3 style="margin:16px 0 8px">Evidence #${e.id} on-chain</h3>${factsHtml(e, data)}<h3 style="margin:16px 0 8px">Custody timeline</h3>${timelineHtml(e)}` : ""}`
              : `<div class="legend">
                  <div class="verdict verdict-ok"><span class="v-icon">${icon("check")}</span><div><div class="v-title">Intact</div><div class="v-sub">Both hashes match registered evidence: the file is bit-for-bit the one that was collected. You also see who held it, and when.</div></div></div>
                  <div class="verdict verdict-bad"><span class="v-icon">${icon("bug")}</span><div><div class="v-title">No match</div><div class="v-sub">Not registered. If it claims to be evidence, it was altered (try the <a href="#/tamper">Tamper Lab</a>).</div></div></div>
                </div>`
          }
        </div>
      </div>`;

    const start = (f) => {
      state.verifyFile = f;
      state.verify = null;
      state.autoVerify = true;
      Shell.render();
    };
    el.querySelector("#verify-file").addEventListener("change", async (ev) => {
      const f = await readInput(ev.target);
      if (f) start({ ...f, origin: "Uploaded file" });
    });
    el.querySelectorAll("[data-pick]").forEach((b) =>
      b.addEventListener("click", () => {
        const x = data.ev(b.dataset.pick);
        start({ ...storedFile(x), origin: `Evidence locker copy of #${x.id}` });
      })
    );
    const lb = el.querySelector("#lookup-btn");
    if (lb)
      lb.addEventListener("click", () => {
        state.verify = { verdict: "lookup", evidenceId: Number(el.querySelector("#lookup").value), items: [], scroll: true };
        state.verifyFile = null;
        Shell.render();
      });
    if (v && v.scroll) {
      v.scroll = false;
      if (matchMedia("(max-width: 860px)").matches) setTimeout(() => el.querySelector("#result-card").scrollIntoView({ block: "start" }), 0);
    }
    const vb = el.querySelector("#verify-btn");
    if (vb) vb.addEventListener("click", () => action(vb, () => verifyFile(state.verifyFile)));
    if (state.autoVerify && file && vb) {
      state.autoVerify = false;
      action(vb, () => verifyFile(file));
    }
  }

  function changeHtml(r) {
    const d = r.detail;
    if (d.kind === "line") {
      const mark = (s) => `${esc(s.slice(0, d.col))}<mark>${esc(s[d.col])}</mark>${esc(s.slice(d.col + 1))}`;
      return `<p class="small">Line ${d.lineNo}: one character changed.</p>
        <div class="diff"><div class="diff-del">- ${mark(d.before)}</div><div class="diff-add">+ ${mark(d.after)}</div></div>`;
    }
    if (d.kind === "delete") return `<p class="small">Line ${d.lineNo} deleted.</p><div class="diff"><div class="diff-del">- ${esc(d.removed)}</div></div>`;
    if (d.kind === "append") return `<p class="small">One byte (${esc(d.byte)}) appended at the end. The file looks exactly the same.</p>`;
    if (d.kind === "bit")
      return `<p class="small">Byte at offset ${d.offset}: 0x${d.before.toString(16).padStart(2, "0")} → 0x${d.after.toString(16).padStart(2, "0")}. One bit out of ${
        r.original.bytes.length * 8
      }.</p>`;
    if (d.kind === "pixel")
      return `<p class="small">Pixel (${d.x}, ${d.y}): rgb(${d.before.join(", ")}) → rgb(${d.after.join(", ")}). Every other pixel is identical.</p>
        <div class="zoom-pair"><figure><img src="${d.zoomBefore}" alt="Original pixels, magnified"><figcaption>Original, 12x</figcaption></figure>
        <figure><img src="${d.zoomAfter}" alt="Edited pixels, magnified"><figcaption>Edited, 12x</figcaption></figure></div>
        <div class="compare"><figure><img src="${r.original.url}" alt="Registered original"><figcaption>Registered original</figcaption></figure>
        <figure><img src="${r.altered.url}" alt="Edited copy"><figcaption>Edited copy</figcaption></figure></div>`;
    if (d.kind === "timestamp")
      return `<p class="small">Timestamp overlay: ${esc(d.before || "(original)")} → <strong>${esc(d.after)}</strong></p>
        <div class="compare"><figure><img src="${r.original.url}" alt="Registered original"><figcaption>Registered original</figcaption></figure>
        <figure><img src="${r.altered.url}" alt="Retimed copy"><figcaption>Forged copy</figcaption></figure></div>`;
    return "";
  }

  async function viewTamper(el, { data, state, action, go }) {
    const F = files();
    const usable = data.evidence.filter((e) => F[e.sha256]);
    const head = pageHead(
      "Tamper Lab",
      "Alter a registered evidence file in your browser and re-hash it. A good hash function has the avalanche effect: one changed character, pixel or bit changes about half of the 256 output bits, in SHA-256 and in SHA3-256, so the altered copy can never pass verification or a hand-over."
    );
    if (!usable.length) {
      el.innerHTML = `${head}<div class="card empty">No evidence files in this browser yet. Click <a href="#/">Load sample case</a> on the Overview or register a file on the <a href="#/investigator">Investigator</a> page.</div>`;
      return;
    }
    const t = (state.tamper = state.tamper || {});
    if (!usable.some((e) => e.id === t.evidenceId)) t.evidenceId = (usable.find((e) => e.pendingTo && e.status === STATUS.InCustody) || usable[0]).id;
    const e = data.ev(t.evidenceId);
    const file = storedFile(e);
    const alts = ES().alterationsFor(file);
    if (!alts.some((a) => a.id === t.alt)) t.alt = alts[0].id;
    const alt = alts.find((a) => a.id === t.alt);
    const r = t.result && t.result.evidenceId === t.evidenceId && t.result.altId === t.alt ? t.result : null;
    const receiver = e.pendingTo && e.status === STATUS.InCustody ? data.members.find((m) => sameAddr(m.address, e.pendingTo)) : null;

    el.innerHTML = `
      ${head}
      <div class="card" style="margin-bottom:16px">
        <div class="tamper-controls">
          <div class="field" style="margin:0"><label for="t-ev">1. Evidence file</label>
            <select id="t-ev">${usable.map((x) => `<option value="${x.id}" ${x.id === e.id ? "selected" : ""}>#${x.id} ${esc(x.fileName)}</option>`).join("")}</select></div>
          <div class="field" style="margin:0"><label>2. Alteration</label>
            <div class="segmented" role="group" aria-label="Alteration">${alts
              .map((a) => `<button type="button" data-alt="${a.id}" class="${a.id === t.alt ? "active" : ""}">${esc(a.label)}</button>`)
              .join("")}</div></div>
        </div>
        <p class="muted small" style="margin:10px 0 0">${esc(alt.hint)}</p>
      </div>
      <div class="card" style="margin-bottom:16px" id="tamper-card">
        ${
          r
            ? `<div class="tamper-grid">
                <div class="tamper-change">
                  <h3>What changed</h3>
                  ${changeHtml(r)}
                  <div class="kv" style="margin-top:10px"><span>Registered file</span><span>${esc(r.original.name)} · ${fmtBytes(r.original.bytes.length)}</span></div>
                  <div class="kv"><span>Altered copy</span><span>${esc(r.altered.name)} · ${fmtBytes(r.altered.bytes.length)}</span></div>
                </div>
                <div class="tamper-hashes">
                  <h3>Both fingerprints</h3>
                  ${hashCompareHtml("SHA-256", e.sha256, r.altered.sha256)}
                  ${hashCompareHtml("SHA3-256", e.sha3, r.altered.sha3)}
                  <p class="muted small">Squares = the 256 output bits; red = flipped. A small change flips about half (128). Changed: <strong id="t-bits-sha256">${r.sha256.bits}</strong> (SHA-256) and <strong id="t-bits-sha3">${r.sha3.bits}</strong> (SHA3-256).</p>
                </div>
              </div>
              <div class="callout callout-bad" style="margin-top:12px">Neither hash of the altered copy is registered, so <strong>Verify Evidence</strong> reports no match and a receiver presenting it to <code>acceptTransfer</code> is rejected with <code>IntegrityMismatch</code>.</div>
              <div class="row" style="margin-top:12px">
                <button type="button" class="btn" id="t-verify">${icon("search")} Check this copy on Verify Evidence</button>
                ${
                  receiver
                    ? `<button type="button" class="btn btn-danger" id="t-swap">${icon("bug")} Swap into the delivery to ${esc(receiver.name)}</button>`
                    : ""
                }
                <button type="button" class="btn btn-secondary" id="t-download">Download altered copy</button>
              </div>
              ${
                receiver
                  ? ""
                  : `<p class="muted small" style="margin-top:8px">Tip: start a hand-over of #${e.id} (for example to the Forensic Lab), then come back to swap this altered copy into the delivery and watch the receiver's acceptance fail.</p>`
              }`
            : `<div class="empty"><span class="spinner"></span><p style="margin-top:8px">Altering and re-hashing…</p></div>`
        }
      </div>
      <div class="grid-2">
        <div class="card"><h2>Why one change breaks everything</h2>
          <p class="small" style="margin-top:8px">SHA-256 mixes every input bit through 64 rounds of additions, rotations and logical functions; SHA3-256 absorbs the input into a 1600-bit Keccak state and permutes it 24 times. In both designs every output bit depends on every input bit, so flipping any single input bit flips each output bit with probability about 1/2. That is why nobody can make a "small" edit that keeps the hash.</p></div>
        <div class="card"><h2>Why two hashes?</h2>
          <p class="small" style="margin-top:8px">SHA-256 (Merkle-Damgård) and SHA3-256 (sponge) are built in completely different ways. Even if a collision attack is ever found for one of them, a forger would also need the same file to collide in the other at the same time. Courts can rely on the record for decades.</p></div>
      </div>`;

    el.querySelector("#t-ev").addEventListener("change", (ev) => {
      t.evidenceId = Number(ev.target.value);
      Shell.render();
    });
    el.querySelectorAll("[data-alt]").forEach((b) =>
      b.addEventListener("click", () => {
        t.alt = b.dataset.alt;
        Shell.render();
      })
    );
    if (r) {
      el.querySelector("#t-verify").addEventListener("click", () => {
        state.verifyFile = { bytes: r.altered.bytes, type: r.altered.type, name: r.altered.name, origin: `Tamper Lab: "${alt.label}" on evidence #${e.id}`, claimId: e.id };
        state.verify = null;
        state.autoVerify = true;
        go("verify");
      });
      el.querySelector("#t-download").addEventListener("click", () => UI.download(r.altered.name, new Blob([r.altered.bytes], { type: r.altered.type })));
      const sw = el.querySelector("#t-swap");
      if (sw)
        sw.addEventListener("click", () => {
          // A forger keeps the original file name: only the re-hash can tell the copies apart.
          putIn("transit", String(e.id), { since: e.pendingSince, name: e.fileName, type: r.altered.type, b64: UI.bytesToBase64(r.altered.bytes) });
          UI.toast(`The altered copy is now in the delivery to ${receiver.name}. Try to accept it there.`, "info", 6000);
          const route = { [ROLE.Analyst]: ["lab", "lab"], [ROLE.Court]: ["court", "court"], [ROLE.Investigator]: ["investigator", "inv"] }[receiver.role];
          state[route[1]] = receiver.address;
          go(route[0]);
        });
    } else {
      const key = `${t.evidenceId}:${t.alt}`;
      if (t.failed === key) el.querySelector("#tamper-card").innerHTML = `<div class="empty">This file could not be altered in this browser.</div>`;
      else if (t.pending !== key) {
        t.pending = key;
        tamper(t.evidenceId, t.alt)
          .then((res) => (t.result = res))
          .catch((err) => {
            t.failed = key;
            UI.toast(err.message, "error");
          })
          .finally(() => {
            t.pending = null;
            Shell.render();
          });
      }
    }
  }

  async function viewAdmin(el, { data, action }) {
    const free = Chain.accounts.slice(1).filter((a) => !data.members.some((m) => sameAddr(m.address, a)));
    const names = new Set(data.members.map((m) => m.name));
    const idea = NEW_MEMBERS.find(([n]) => !names.has(n)) || ["", ROLE.Investigator];
    const holds = (m) => data.evidence.filter((e) => sameAddr(e.custodian, m.address) && e.status === STATUS.InCustody).length;
    el.innerHTML = `
      ${pageHead(
        "State Forensic Authority",
        `Acting as <code>${esc(UI.short(authority(), 4))}</code> (contract deployer). The authority runs the permissioned consortium: it admits police units, forensic labs and courts with a role, and can suspend them.`
      )}
      <div class="grid-2" style="align-items:start;margin-bottom:16px">
        <form class="card" id="admit-form" autocomplete="off">
          <div class="card-head"><h2>Admit a member</h2></div>
          ${
            free.length
              ? `<div class="field"><label for="f-acct">Account</label><select id="f-acct">${free.map((a) => `<option value="${a}">${esc(UI.short(a, 6))}</option>`).join("")}</select></div>
                 <div class="field"><label for="f-name">Agency name</label><input id="f-name" type="text" required maxlength="60" value="${esc(idea[0])}"></div>
                 <div class="field"><label for="f-role">Role</label><select id="f-role">${[ROLE.Investigator, ROLE.Analyst, ROLE.Court]
                   .map((r) => `<option value="${r}" ${r === idea[1] ? "selected" : ""}>${ROLE_LABEL[r]}</option>`)
                   .join("")}</select></div>
                 <button class="btn" type="submit" id="admit-btn">${icon("users")} Admit member</button>`
              : `<p class="muted">All demo accounts are already members.</p>`
          }
        </form>
        <div class="card">
          <div class="card-head"><h2>Why a permissioned consortium?</h2></div>
          <ul class="bullets">
            <li>Evidence handling is a legal duty: only vetted agencies may <strong>register</strong>, <strong>hold</strong> or <strong>rule on</strong> evidence, but anyone may <strong>verify</strong> a file.</li>
            <li>The smart contract enforces the roles: investigators collect, analysts attach reports, courts admit.</li>
            <li>Suspending a member stops it at once. Its past custody records stay on-chain.</li>
            <li>Every decision of the authority is itself an on-chain event, so the authority is auditable too.</li>
          </ul>
        </div>
      </div>
      <div class="card">
        <div class="card-head"><h2>Members</h2><span class="muted small">Only the State Forensic Authority can change this list.</span></div>
        <div class="table-wrap"><table class="table"><thead><tr><th>Name</th><th>Role</th><th>Account</th><th>Holds</th><th>Status</th><th></th></tr></thead><tbody>
        ${data.members
          .map(
            (m) => `<tr><td data-label="Name"><strong>${esc(m.name)}</strong></td>
            <td data-label="Role"><span class="chip">${ROLE_LABEL[m.role]}</span></td>
            <td data-label="Account"><code>${esc(UI.short(m.address, 4))}</code></td>
            <td data-label="Holds">${holds(m)} item(s)</td>
            <td data-label="Status">${activeChip(m)}</td>
            <td><button class="btn btn-secondary btn-sm" data-toggle="${m.address}" data-active="${m.active}">${m.active ? "Suspend" : "Re-activate"}</button></td></tr>`
          )
          .join("")}</tbody></table></div>
      </div>`;
    const form = el.querySelector("#admit-form");
    if (el.querySelector("#admit-btn"))
      form.addEventListener("submit", (ev) => {
        ev.preventDefault();
        const name = form.querySelector("#f-name").value.trim();
        action(el.querySelector("#admit-btn"), async () => {
          await Chain.send(authority(), "registerMember", [form.querySelector("#f-acct").value, Number(form.querySelector("#f-role").value), name]);
          UI.toast(`${name} admitted to the consortium`, "success");
        });
      });
    el.querySelectorAll("[data-toggle]").forEach((b) =>
      b.addEventListener("click", () =>
        action(b, async () => {
          const on = b.dataset.active !== "true";
          await Chain.send(authority(), "setMemberActive", [b.dataset.toggle, on]);
          UI.toast(`${Chain.label(b.dataset.toggle)} ${on ? "re-activated" : "suspended"}`, "success");
        })
      )
    );
  }

  function formatEvent(ev) {
    const a = ev.args;
    switch (ev.name) {
      case "MemberRegistered":
        return `${a.name} joined the consortium as ${["a member", "an investigator", "a forensic analyst", "a court"][Number(a.role)]}`;
      case "MemberStatusChanged":
        return `${Chain.label(a.account)} ${a.active ? "re-activated" : "suspended"} by the State Forensic Authority`;
      case "CaseCreated":
        return `${Chain.label(a.by)} opened case ${a.caseNumber} "${a.title}"`;
      case "EvidenceRegistered":
        return `${Chain.label(a.by)} registered evidence #${a.evidenceId} "${a.fileName}" in case #${a.caseId}${
          Number(a.parentId) ? `, derived from #${a.parentId}` : ""
        } · SHA-256 ${UI.short(a.sha256Hash, 4)} · SHA3-256 ${UI.short(a.sha3Hash, 4)}`;
      case "TransferInitiated":
        return `${Chain.label(a.from)} started handing #${a.evidenceId} to ${Chain.label(a.to)}: ${a.purpose}`;
      case "TransferCancelled":
        return `Hand-over of #${a.evidenceId} cancelled by ${Chain.label(a.by)}`;
      case "TransferAccepted":
        return `${Chain.label(a.to)} accepted #${a.evidenceId} from ${Chain.label(a.from)} · re-hash ${UI.short(a.verifiedHash, 4)} matched`;
      case "IntegrityChecked":
        return a.matched
          ? `${Chain.label(a.by)} re-hashed #${a.evidenceId}: intact`
          : `TAMPER ALARM on #${a.evidenceId}: ${Chain.label(a.by)} presented a copy with hash ${UI.short(a.presentedHash, 4)}, which does not match`;
      case "AnalysisReportAdded":
        return `${Chain.label(a.analyst)} anchored an analysis report for #${a.evidenceId} (${UI.short(a.reportHash, 4)}): ${a.summary}`;
      case "EvidenceAdmitted":
        return `${Chain.label(a.court)} admitted #${a.evidenceId} as evidence`;
      case "EvidenceInadmissible":
        return `${Chain.label(a.court)} ruled #${a.evidenceId} inadmissible: ${a.reason}`;
      default:
        return "";
    }
  }

  async function viewExplorer(el) {
    el.innerHTML = `${pageHead(
      "Blockchain Explorer",
      "Every registration, hand-over, integrity check, report and court decision is a transaction in a block. Each block stores the hash of the previous one, so back-dating or deleting a custody record would break the chain."
    )}<div id="explorer-host"></div>`;
    await Explorer.render(el.querySelector("#explorer-host"), { formatEvent });
  }

  async function viewAbout(el) {
    const ok = await CC().selfTest();
    el.innerHTML = `
      ${pageHead("About the project", "CustodyChain: a blockchain-based digital evidence integrity system with dual hashing (SHA-256 + SHA3-256), verified hand-overs and a permissioned consortium.")}
      <div class="stack">
        <div class="card">
          <h2>Problem</h2>
          <p style="margin-top:8px">Digital evidence is just bytes. A CCTV still, a server log or a chat export can be edited, swapped for another copy or simply disputed in court ("is this really the file you seized?"). The paper chain-of-custody register that should answer that question is easy to back-date, fake or lose, and each agency keeps its own.</p>
          <h2 style="margin-top:14px">Solution</h2>
          <ul class="bullets">
            <li><strong>Dual fingerprints:</strong> the SHA-256 and SHA3-256 hashes of every file are recorded when it is collected. Any change, even one bit, changes both completely.</li>
            <li><strong>Verified hand-overs:</strong> custody moves only when the receiver presents the matching hash of the copy it received. The smart contract checks it.</li>
            <li><strong>Tamper alarms:</strong> a failed check is stored permanently and blocks admission.</li>
            <li><strong>Analysis and lineage:</strong> report hashes and derived files are linked to the original evidence.</li>
            <li><strong>Court and public verification:</strong> the court admits only evidence it verified itself and prints an Evidence Integrity Certificate; anyone can check a file and see its custody timeline.</li>
          </ul>
        </div>
        <div class="card">
          <h2>Syllabus mapping (22CS743)</h2>
          <div class="table-wrap" style="margin-top:8px"><table class="table"><thead><tr><th>Module</th><th>Concept</th><th>Where it is used</th></tr></thead><tbody>
            <tr><td data-label="Module">II</td><td data-label="Concept">Hash functions: SHA-256 and SHA-3 (Keccak family, FIPS 202), avalanche effect, hash-linked blocks</td><td data-label="Used in">Every file is fingerprinted twice in the browser; the Tamper Lab shows one changed pixel or byte flipping about half of the 256 output bits of both hashes; the explorer checks each block's previous-hash link</td></tr>
            <tr><td data-label="Module">III</td><td data-label="Concept">Ethereum, EVM, smart contracts, accounts and signed transactions</td><td data-label="Used in"><code>EvidenceRegistry.sol</code> enforces the custody rules (two-step transfer with hash check, tamper alarms, admission conditions) with custom errors and events; every action is a transaction signed by the member's account</td></tr>
            <tr><td data-label="Module">IV</td><td data-label="Concept">Permissioned / consortium blockchain</td><td data-label="Used in">The State Forensic Authority admits police units, forensic labs and courts with roles and can suspend them; only members can act, anyone can read</td></tr>
            <tr><td data-label="Module">V</td><td data-label="Concept">Applications: digital forensics, access control, security, privacy</td><td data-label="Used in">Tamper-evident audit trail and Evidence Integrity Certificate for legal admissibility; role-based access control; the files stay off-chain, only hashes are public</td></tr>
          </tbody></table></div>
        </div>
        <div class="grid-2">
          <div class="card">
            <h2>On-chain vs off-chain</h2>
            <ul class="bullets">
              <li><strong>On-chain:</strong> members and roles, cases, both hashes of every file, file name, size, description, collection time, current custodian, and the custody log: every hand-over, integrity check, report hash and court decision.</li>
              <li><strong>Off-chain:</strong> the evidence files and reports themselves. The demo keeps files up to 512 KB in browser storage (the "evidence locker"); larger files are only hashed.</li>
            </ul>
            <p class="small muted" style="margin-top:8px">Self-test: SHA-256("abc") and SHA3-256("abc") = <code>${UI.short(CC().SHA3_ABC, 6)}</code> ${
              ok ? `<span class="chip chip-ok" id="selftest">FIPS test vectors correct, SHA3 differs from keccak256</span>` : `<span class="chip chip-bad" id="selftest">failed</span>`
            }</p>
          </div>
          <div class="card">
            <h2>Technology</h2>
            <ul class="bullets">
              <li>Solidity 0.8.24 smart contract, Hardhat (local blockchain + tests)</li>
              <li>In-browser Ethereum chain (Ganache) for zero-install demos</li>
              <li>ethers.js v6, Web Crypto API (SHA-256), js-sha3 (SHA3-256)</li>
              <li>Canvas API for the sample CCTV still, thumbnails and pixel edits</li>
              <li>HTML, CSS and JavaScript (no build step), hosted on GitHub Pages</li>
            </ul>
          </div>
        </div>
        <div class="card callout-warn">
          <h2>Limitations</h2>
          <ul class="bullets">
            <li>A hash proves that a file has not changed since it was registered, not that it was genuine when collected. A staged photo hashes just as well, so collection procedures still matter.</li>
            <li>File names and descriptions are public on-chain. A real system would encrypt sensitive metadata or store only its hash, to protect victims and suspects.</li>
            <li>In the demo all members share one browser and one evidence locker; the "received copy" is the locker copy unless you upload your own file.</li>
            <li>A production deployment would run on a permissioned network operated by the consortium (for example Hyperledger Besu) with hardware-backed keys for each agency.</li>
          </ul>
        </div>
      </div>`;
  }

  // ------------------------------------------------------------------
  Shell.start({
    brand: { name: "CustodyChain", tagline: "Blockchain-based digital evidence integrity", icon: "check" },
    timeTravel: false,
    load,
    chain: {
      storageKey: "custodychain",
      artifact: window.CONTRACT_ARTIFACT,
      errors: ERRORS,
      async isSeeded(chain) {
        const [accts] = await chain.contract.getMembers();
        return accts.length > 0;
      },
      async seed(chain) {
        for (const [i, role, name] of CONSORTIUM) await chain.send(chain.accounts[0], "registerMember", [chain.accounts[i], role, name]);
      },
    },
    routes: [
      { id: "home", title: "Overview", icon: "home", render: viewHome },
      { id: "investigator", title: "Investigator", icon: "shield", section: "Roles", render: viewInvestigator },
      { id: "lab", title: "Forensic Lab", icon: "cpu", section: "Roles", render: viewLab },
      { id: "court", title: "Court", icon: "building", section: "Roles", render: viewCourt },
      { id: "verify", title: "Verify Evidence", icon: "search", section: "Public", render: viewVerify },
      { id: "tamper", title: "Tamper Lab", icon: "bug", section: "Public", render: viewTamper },
      { id: "admin", title: "Forensic Authority", icon: "users", section: "Consortium", render: viewAdmin },
      { id: "explorer", title: "Blockchain Explorer", icon: "blocks", section: "Consortium", render: viewExplorer },
      { id: "about", title: "About & Syllabus", icon: "book", section: "Project", render: viewAbout },
    ],
  });

  // Exposed for automated tests.
  window.CustodyApp = {
    load,
    createCase,
    registerEvidence,
    quickRegister,
    loadDemoCase,
    initiateTransfer,
    cancelTransfer,
    acceptTransfer,
    verifyIntegrity,
    addReport,
    deriveEvidence,
    admit,
    markInadmissible,
    verifyFile,
    tamper,
    certificateText,
    sampleFile,
  };
})();
