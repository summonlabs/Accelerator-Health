// Copyright 2026 Summon Software Labs
// Licensed under the Apache License, Version 2.0 (the "License"); see LICENSE.
// Regression tests for the store's fencing, recovery, readiness and persistence
// invariants and for the coordinator process (fenced reports, superseded worker
// incarnations, state-file recovery and the configured coordinator epoch).
#include "accelerator-health/Messages.hpp"
#include "accelerator-health/Net.hpp"
#include "accelerator-health/Persistence.hpp"
#include "accelerator-health/Readiness.hpp"
#include "accelerator-health/StateMachine.hpp"
#include "accelerator-health/Store.hpp"
#include "accelerator-health/Time.hpp"
#include "accelerator-health/Util.hpp"
#include "test_fw.hpp"

#include <atomic>
#include <cstdio>
#include <exception>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef NOGDI
#define NOGDI
#endif
#include <winsock2.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

using namespace ah;

namespace {

bool g_processTests = true;

std::shared_ptr<FakeClock> clk() { return std::make_shared<FakeClock>(0); }

std::string tempPath(const char* tag) {
  static int counter = 0;
#ifdef _WIN32
  const unsigned long pid = GetCurrentProcessId();
#else
  const unsigned long pid = static_cast<unsigned long>(getpid());
#endif
  return std::string(AH_BINARY_DIR) + "/ah_regression_" + std::to_string(pid) + "_" + std::to_string(++counter) + "_" +
         tag + ".bin";
}

AcceleratorObservation obsFor(AcceleratorId id, WorkerId w, WorkerBootId b, Timestamp ts) {
  AcceleratorObservation o;
  o.accelerator = id;
  o.node = NodeId{1};
  o.worker = w;
  o.workerBootId = b;
  o.observationGeneration = ObservationGeneration{1};
  o.deviceGeneration = DeviceGeneration{1};
  o.timestamp = ts;
  o.dimensions = {nominal(DimensionKind::ENUMERATION, EvidenceClass::MEASURED, ts),
                  nominal(DimensionKind::EXECUTION, EvidenceClass::MEASURED, ts),
                  nominal(DimensionKind::MEMORY_INTEGRITY, EvidenceClass::MEASURED, ts)};
  return o;
}

AuthorityEnvelope envFor(std::uint64_t epoch, WorkerId w, WorkerBootId b, std::uint64_t obsGen,
                         std::uint64_t deviceGen = 1) {
  AuthorityEnvelope e;
  e.coordinatorEpoch = epoch;
  e.workerId = w;
  e.workerBootId = b;
  e.observationGeneration = ObservationGeneration{obsGen};
  e.validationGeneration = ValidationGeneration{obsGen};
  e.deviceGeneration = DeviceGeneration{deviceGen};
  return e;
}

ValidationRecord fullVal(AcceleratorId id, std::uint64_t run, Timestamp ts, bool passed = true,
                         std::uint64_t deviceGen = 1) {
  ValidationRecord v;
  v.id = ValidationRunId{run};
  v.accelerator = id;
  v.timestamp = ts;
  v.profile = ValidationProfile::FULL;
  v.depth = ValidationDepth::FULL;
  v.passed = passed;
  v.validationGeneration = ValidationGeneration{1};
  v.deviceGeneration = DeviceGeneration{deviceGen};
  return v;
}

Fault transientFault(AcceleratorId id, std::uint64_t fid, Timestamp ts) {
  Fault f;
  f.id = FaultId{fid};
  f.accelerator = id;
  f.type = FaultType::TRANSFER_FAILURE;
  f.faultClass = FaultClass::TRANSIENT;
  f.severity = Severity::DEGRADED;
  f.timestamp = ts;
  f.transient = true;
  f.recoverable = true;
  f.evidence = "synthetic";
  return f;
}

bool rejected(const std::string& r) { return r.rfind("rejected", 0) == 0; }

// ---- Persistence crafting: one device record lifted out of a real encoding ----
std::vector<std::uint8_t> bodyOf(const std::vector<std::uint8_t>& frame) {
  const std::uint32_t len = util::load_le32(frame.data() + 8);
  return std::vector<std::uint8_t>(frame.begin() + 12, frame.begin() + 12 + len);
}

std::vector<std::uint8_t> frameOf(const std::vector<std::uint8_t>& like, const std::vector<std::uint8_t>& body) {
  std::vector<std::uint8_t> out(like.begin(), like.begin() + 8);  // magic + schema version
  std::uint8_t b4[4];
  util::store_le(static_cast<std::uint32_t>(body.size()), b4);
  out.insert(out.end(), b4, b4 + 4);
  out.insert(out.end(), body.begin(), body.end());
  util::store_le(util::crc32(out.data(), out.size()), b4);
  out.insert(out.end(), b4, b4 + 4);
  return out;
}

struct Crafted {
  std::vector<std::uint8_t> like;      // a genuine encoding (header source)
  std::vector<std::uint8_t> head;      // policy, policy generation and epoch
  std::vector<std::uint8_t> trailing;  // whatever follows the device records
};

// Encodes an empty store and returns the pieces around the device records.
Crafted craftedBase() {
  HealthStore empty(clk(), {}, 1);
  Crafted c;
  c.like = empty.encodeState();
  const auto body = bodyOf(c.like);
  wire::Writer pw;
  HealthPolicy{}.write(pw);
  const std::size_t head = pw.data().size() + 8 + 8;  // policy, policy generation, epoch
  c.head.assign(body.begin(), body.begin() + static_cast<std::ptrdiff_t>(head));
  c.trailing.assign(body.begin() + static_cast<std::ptrdiff_t>(head) + 4, body.end());
  return c;
}

// The encoded record of a single freshly registered device.
std::vector<std::uint8_t> deviceRecord(std::uint64_t uuid) {
  HealthStore one(clk(), {}, 1);
  one.registerDevice(DeviceUuid{uuid}, NodeId{1});
  const auto body = bodyOf(one.encodeState());
  const Crafted base = craftedBase();
  const std::size_t start = base.head.size() + 4;
  const std::size_t len = body.size() - (base.head.size() + 4 + base.trailing.size());
  return std::vector<std::uint8_t>(body.begin() + static_cast<std::ptrdiff_t>(start),
                                   body.begin() + static_cast<std::ptrdiff_t>(start + len));
}

std::vector<std::uint8_t> craftState(const std::vector<std::vector<std::uint8_t>>& records) {
  const Crafted base = craftedBase();
  std::vector<std::uint8_t> body = base.head;
  std::uint8_t b4[4];
  util::store_le(static_cast<std::uint32_t>(records.size()), b4);
  body.insert(body.end(), b4, b4 + 4);
  for (const auto& r : records) body.insert(body.end(), r.begin(), r.end());
  body.insert(body.end(), base.trailing.begin(), base.trailing.end());
  return frameOf(base.like, body);
}

constexpr std::size_t kRecordIdOffset = 0;           // AcceleratorId
constexpr std::size_t kRecordGenerationOffset = 40;  // DeviceGeneration
constexpr std::size_t kRecordStateOffset = 48;       // HealthState

}  // namespace

// A prior worker incarnation that was superseded by a restart cannot register
// again and take authority back, also across a coordinator restart.
AH_TEST(superseded_worker_boot_cannot_reregister) {
  HealthStore s(clk(), {}, 1);
  const auto id = s.registerDevice(DeviceUuid{11}, NodeId{1});
  const WorkerId w{1};
  s.registerWorker(w, WorkerBootId{1});
  s.registerWorker(w, WorkerBootId{2});
  s.registerWorker(w, WorkerBootId{1});
  const auto stale = s.acceptObservation(obsFor(id, w, WorkerBootId{1}, Timestamp{10}), envFor(1, w, WorkerBootId{1}, 1));
  CHECK_MSG(rejected(stale), stale.c_str());
  const auto current = s.acceptObservation(obsFor(id, w, WorkerBootId{2}, Timestamp{11}), envFor(1, w, WorkerBootId{2}, 1));
  CHECK_MSG(current == "accepted", current.c_str());

  // The superseded registration had already been dropped by a disconnect.
  s.invalidateWorker(w, WorkerBootId{2}, Timestamp{12});
  s.registerWorker(w, WorkerBootId{3});
  s.invalidateWorker(w, WorkerBootId{3}, Timestamp{13});
  s.registerWorker(w, WorkerBootId{2});
  const auto stale2 = s.acceptObservation(obsFor(id, w, WorkerBootId{2}, Timestamp{14}), envFor(1, w, WorkerBootId{2}, 2));
  CHECK_MSG(rejected(stale2), stale2.c_str());

  // The retirement is part of the persisted state.
  HealthStore restored(clk(), {}, 1);
  std::string err;
  CHECK_MSG(HealthStore::decode(s.encodeState(), restored, &err), err.c_str());
  restored.registerWorker(w, WorkerBootId{1});
  const auto stale3 = restored.acceptObservation(obsFor(id, w, WorkerBootId{1}, Timestamp{15}), envFor(1, w, WorkerBootId{1}, 7));
  CHECK_MSG(rejected(stale3), stale3.c_str());
  restored.registerWorker(w, WorkerBootId{3});
  const auto current3 = restored.acceptObservation(obsFor(id, w, WorkerBootId{3}, Timestamp{16}), envFor(1, w, WorkerBootId{3}, 1));
  CHECK_MSG(current3 == "accepted", current3.c_str());
}

// A failed revalidation ends the recovery attempt: the device stays quarantined
// and only a new explicit recovery with a fresh run of the policy's required
// successful validations returns it to service.
AH_TEST(failed_revalidation_ends_recovery_attempt) {
  try {
    HealthPolicy pol;
    pol.recoveryValidationsRequired = 2;
    HealthStore s(clk(), pol, 1);
    const auto id = s.registerDevice(DeviceUuid{21}, NodeId{1});
    const WorkerId w{1};
    const WorkerBootId b{1};
    s.registerWorker(w, b);
    s.acceptObservation(obsFor(id, w, b, Timestamp{10}), envFor(1, w, b, 1));
    s.recordValidation(fullVal(id, 1, Timestamp{20}));
    s.beginQuarantine(id, QuarantineAuthority::OPERATOR, "operator hold", "operator");
    s.clearQuarantine(id);
    s.beginRecovery(id);
    auto snap = s.revalidate(id, fullVal(id, 2, Timestamp{30}));
    CHECK_EQ(static_cast<int>(snap.state), static_cast<int>(HealthState::REVALIDATING));
    snap = s.revalidate(id, fullVal(id, 3, Timestamp{40}, false));
    CHECK_EQ(static_cast<int>(snap.state), static_cast<int>(HealthState::QUARANTINED));
    CHECK(!snap.latestAssessment.inRecovery);
    CHECK(!snap.latestAssessment.executionReady);
    snap = s.revalidate(id, fullVal(id, 4, Timestamp{50}));
    CHECK_EQ(static_cast<int>(snap.state), static_cast<int>(HealthState::QUARANTINED));
    CHECK(!snap.latestAssessment.executionReady);
    s.beginRecovery(id);
    snap = s.revalidate(id, fullVal(id, 5, Timestamp{60}));
    CHECK_EQ(static_cast<int>(snap.state), static_cast<int>(HealthState::REVALIDATING));
    snap = s.revalidate(id, fullVal(id, 6, Timestamp{70}));
    CHECK_EQ(static_cast<int>(snap.state), static_cast<int>(HealthState::HEALTHY));
    CHECK(snap.latestAssessment.executionReady);
  } catch (const std::exception& ex) {
    CHECK_MSG(false, std::string("unexpected exception: ") + ex.what());
  }
}

// Degraded readiness is subject to the same validation, generation and
// recovery gates as healthy readiness.
AH_TEST(degraded_readiness_is_gated) {
  const WorkerId w{1};
  const WorkerBootId b{1};
  {
    HealthStore s(clk(), {}, 1);
    const auto id = s.registerDevice(DeviceUuid{31}, NodeId{1});
    s.registerWorker(w, b);
    s.acceptObservation(obsFor(id, w, b, Timestamp{10}), envFor(1, w, b, 1));
    CHECK_EQ(static_cast<int>(s.snapshot(id).readiness), static_cast<int>(ReadinessState::REVALIDATION_REQUIRED));
    s.recordFault(transientFault(id, 1, Timestamp{20}));
    s.recordFault(transientFault(id, 2, Timestamp{30}));
    const auto snap = s.snapshot(id);
    CHECK_EQ(static_cast<int>(snap.state), static_cast<int>(HealthState::DEGRADED));
    CHECK(!snap.latestAssessment.executionReady);
    CHECK(snap.readiness != ReadinessState::READY_DEGRADED);
  }
  {
    HealthStore s(clk(), {}, 1);
    const auto id = s.registerDevice(DeviceUuid{32}, NodeId{1});
    s.registerWorker(w, b);
    s.acceptObservation(obsFor(id, w, b, Timestamp{10}), envFor(1, w, b, 1));
    s.recordValidation(fullVal(id, 1, Timestamp{15}));
    s.recordFault(transientFault(id, 1, Timestamp{20}));
    s.recordFault(transientFault(id, 2, Timestamp{30}));
    CHECK_EQ(static_cast<int>(s.snapshot(id).state), static_cast<int>(HealthState::DEGRADED));
    CHECK(s.snapshot(id).latestAssessment.executionReady);
    const std::string p = tempPath("degraded");
    std::string err;
    CHECK_MSG(s.saveToFile(p, &err), err.c_str());
    HealthStore r(clk(), {}, 1);
    CHECK_MSG(HealthStore::loadFromFile(p, r, &err), err.c_str());
    const auto snap = r.snapshot(id);
    CHECK(!snap.latestAssessment.executionReady);
    CHECK_EQ(static_cast<int>(snap.readiness), static_cast<int>(ReadinessState::REVALIDATION_REQUIRED));
    std::remove(p.c_str());
  }
  ReadinessInput in;
  in.health = HealthState::DEGRADED;
  in.freshness = FreshnessStatus::CURRENT;
  in.validationDepth = ValidationDepth::FULL;
  in.requiredValidationDepth = ValidationDepth::FULL;
  in.allowDegradedReadiness = true;
  CHECK(ReadinessEvaluator{}.evaluate(in).executionReady);
  in.deviceGenerationChanged = true;
  CHECK(!ReadinessEvaluator{}.evaluate(in).executionReady);
  in.deviceGenerationChanged = false;
  in.policyGenerationChanged = true;
  CHECK(!ReadinessEvaluator{}.evaluate(in).executionReady);
  in.policyGenerationChanged = false;
  in.validationDepth = ValidationDepth::ENUMERATION_ONLY;
  CHECK(!ReadinessEvaluator{}.evaluate(in).executionReady);
}

// A rejected load leaves the target store untouched, and loads reject duplicate
// device ids and null device generations.
AH_TEST(rejected_load_is_atomic_and_strict) {
  HealthStore target(clk(), {}, 9);
  const auto keep = target.registerDevice(DeviceUuid{77}, NodeId{1});
  auto bad = deviceRecord(42);
  bad[kRecordStateOffset] = 0xEE;
  std::string err;
  CHECK(!HealthStore::decode(craftState({deviceRecord(41), bad}), target, &err));
  const auto ids = target.deviceIds();
  CHECK(ids.size() == 1u && ids[0] == keep);
  CHECK_EQ(target.coordinatorEpoch(), 9u);

  HealthStore probe(clk(), {}, 1);
  CHECK_MSG(HealthStore::decode(craftState({deviceRecord(41), deviceRecord(42)}), probe, &err), err.c_str());
  auto dup = deviceRecord(42);
  const auto first = deviceRecord(41);
  for (std::size_t i = 0; i < 8; ++i) dup[kRecordIdOffset + i] = first[kRecordIdOffset + i];
  HealthStore s2(clk(), {}, 1);
  CHECK_MSG(!HealthStore::decode(craftState({first, dup}), s2, &err), "duplicate device id must be rejected");
  auto nullGen = deviceRecord(43);
  for (std::size_t i = 0; i < 8; ++i) nullGen[kRecordGenerationOffset + i] = 0;
  HealthStore s3(clk(), {}, 1);
  CHECK_MSG(!HealthStore::decode(craftState({nullGen}), s3, &err), "null device generation must be rejected");
}

// A device-generation change requires a validation of the new generation; a
// disconnect of the reporting worker does not discharge that requirement.
AH_TEST(device_generation_change_requires_revalidation) {
  try {
    const WorkerId w{1};
    {
      HealthStore s(clk(), {}, 1);
      const auto id = s.registerDevice(DeviceUuid{51}, NodeId{1});
      s.registerWorker(w, WorkerBootId{1});
      s.acceptObservation(obsFor(id, w, WorkerBootId{1}, Timestamp{10}), envFor(1, w, WorkerBootId{1}, 1));
      s.recordValidation(fullVal(id, 1, Timestamp{15}));
      CHECK_EQ(static_cast<int>(s.snapshot(id).readiness), static_cast<int>(ReadinessState::READY));
      const auto reset = s.acceptObservation(obsFor(id, w, WorkerBootId{1}, Timestamp{20}),
                                             envFor(1, w, WorkerBootId{1}, 2, 2));
      CHECK_MSG(reset == "accepted", reset.c_str());
      CHECK_EQ(static_cast<int>(s.snapshot(id).readiness), static_cast<int>(ReadinessState::REVALIDATION_REQUIRED));
      s.recordValidation(fullVal(id, 2, Timestamp{25}, true, 1));  // the previous generation
      CHECK_EQ(static_cast<int>(s.snapshot(id).readiness), static_cast<int>(ReadinessState::REVALIDATION_REQUIRED));
      s.recordValidation(fullVal(id, 3, Timestamp{26}, true, 2));  // the new generation
      CHECK_EQ(static_cast<int>(s.snapshot(id).readiness), static_cast<int>(ReadinessState::READY));
    }
    {
      HealthStore s(clk(), {}, 1);
      const auto id = s.registerDevice(DeviceUuid{52}, NodeId{1});
      s.registerWorker(w, WorkerBootId{1});
      s.acceptObservation(obsFor(id, w, WorkerBootId{1}, Timestamp{10}), envFor(1, w, WorkerBootId{1}, 1));
      s.recordValidation(fullVal(id, 1, Timestamp{15}));
      s.acceptObservation(obsFor(id, w, WorkerBootId{1}, Timestamp{20}), envFor(1, w, WorkerBootId{1}, 2, 2));
      s.invalidateWorker(w, WorkerBootId{1}, Timestamp{30});
      s.registerWorker(w, WorkerBootId{2});
      s.acceptObservation(obsFor(id, w, WorkerBootId{2}, Timestamp{40}), envFor(1, w, WorkerBootId{2}, 1, 2));
      // Operator recovery whose revalidation ran on the previous generation.
      s.beginQuarantine(id, QuarantineAuthority::OPERATOR, "reset", "operator");
      s.clearQuarantine(id);
      s.beginRecovery(id);
      auto snap = s.revalidate(id, fullVal(id, 2, Timestamp{50}, true, 1));
      CHECK_EQ(static_cast<int>(snap.state), static_cast<int>(HealthState::HEALTHY));
      CHECK(!snap.latestAssessment.executionReady);
      CHECK_EQ(static_cast<int>(snap.readiness), static_cast<int>(ReadinessState::REVALIDATION_REQUIRED));
      s.recordValidation(fullVal(id, 3, Timestamp{55}, true, 2));
      snap = s.snapshot(id);
      CHECK_EQ(static_cast<int>(snap.readiness), static_cast<int>(ReadinessState::READY));
      CHECK(snap.latestAssessment.executionReady);
    }
  } catch (const std::exception& ex) {
    CHECK_MSG(false, std::string("unexpected exception: ") + ex.what());
  }
}

// HEALTHY is reachable only from INITIALIZING, OFFLINE or REVALIDATING.
AH_TEST(healthy_only_from_documented_states) {
  for (const auto& kv : kHealthStateNames) {
    if (canTransition(kv.first, HealthState::HEALTHY)) {
      CHECK_MSG(kv.first == HealthState::INITIALIZING || kv.first == HealthState::OFFLINE ||
                    kv.first == HealthState::REVALIDATING,
                kv.second);
    }
  }
  StateMachine m;
  bool threw = false;
  try { m.transitionTo(HealthState::HEALTHY); } catch (const InvalidTransition&) { threw = true; }
  CHECK_MSG(threw, "UNKNOWN->HEALTHY must be illegal");
}

// Evidence is attributed to the fenced reporting incarnation, so its disconnect
// strips that evidence even when the observation body names another worker.
AH_TEST(disconnect_strips_evidence_reported_under_its_authority) {
  HealthStore s(clk(), {}, 1);
  const auto id = s.registerDevice(DeviceUuid{71}, NodeId{1});
  s.registerWorker(WorkerId{2}, WorkerBootId{200});
  const auto res = s.acceptObservation(obsFor(id, WorkerId{10}, WorkerBootId{100}, Timestamp{10}),
                                       envFor(1, WorkerId{2}, WorkerBootId{200}, 1));
  CHECK_MSG(res == "accepted", res.c_str());
  s.recordValidation(fullVal(id, 1, Timestamp{20}));
  CHECK(s.snapshot(id).latestAssessment.executionReady);
  s.invalidateWorker(WorkerId{2}, WorkerBootId{200}, Timestamp{30});
  CHECK(!s.snapshot(id).latestAssessment.executionReady);
}

// Snapshots and saves read the store under its lock: every encoding taken while
// another thread registers devices is a consistent, decodable state.
AH_TEST(encode_is_consistent_under_concurrent_updates) {
  HealthStore s(clk(), {}, 1);
  constexpr std::uint64_t kDevices = 3000;
  std::atomic<bool> go{false};
  std::atomic<bool> done{false};
  std::thread writer([&] {
    while (!go.load()) std::this_thread::yield();
    for (std::uint64_t u = 1; u <= kDevices; ++u) s.registerDevice(DeviceUuid{u}, NodeId{1});
    done = true;
  });
  int encodes = 0;
  int failed = 0;
  std::string firstError;
  go = true;
  while (!done.load() || encodes == 0) {
    HealthStore view(clk(), {}, 0);
    std::string err;
    if (!HealthStore::decode(s.encodeState(), view, &err)) {
      if (failed++ == 0) firstError = err;
    }
    ++encodes;
  }
  writer.join();
  CHECK_MSG(failed == 0, std::to_string(failed) + " of " + std::to_string(encodes) + " encodings failed to decode: " +
                             firstError);
  HealthStore view(clk(), {}, 0);
  std::string err;
  CHECK_MSG(HealthStore::decode(s.encodeState(), view, &err), err.c_str());
  CHECK_EQ(view.deviceIds().size(), static_cast<std::size_t>(kDevices));
}

#if defined(_WIN32) && defined(AH_COORDINATOR_EXE)
namespace {

std::vector<std::uint8_t> readFile(const std::string& p) {
  std::ifstream is(p, std::ios::binary);
  return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
}

void writeFile(const std::string& p, const std::vector<std::uint8_t>& bytes) {
  std::ofstream os(p, std::ios::binary | std::ios::trunc);
  os.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

Fault fatalFault(AcceleratorId id, std::uint64_t fid, Timestamp ts) {
  Fault f;
  f.id = FaultId{fid};
  f.accelerator = id;
  f.type = FaultType::DEVICE_LOST;
  f.faultClass = FaultClass::FATAL;
  f.severity = Severity::FATAL;
  f.timestamp = ts;
  f.fatal = true;
  f.evidence = "synthetic";
  return f;
}

bool readLine(HANDLE h, std::string& line) {
  line.clear();
  for (;;) {
    char c = 0;
    DWORD n = 0;
    if (!ReadFile(h, &c, 1, &n, nullptr) || n == 0) return !line.empty();
    if (c == '\n') return true;
    if (c != '\r') line.push_back(c);
  }
}

std::uint16_t freeLoopbackPort() {
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = 0;
  int len = static_cast<int>(sizeof(a));
  std::uint16_t port = 0;
  if (s != INVALID_SOCKET && bind(s, reinterpret_cast<sockaddr*>(&a), len) == 0 &&
      getsockname(s, reinterpret_cast<sockaddr*>(&a), &len) == 0) {
    port = ntohs(a.sin_port);
  }
  if (s != INVALID_SOCKET) closesocket(s);
  return port;
}

// One ah-coordinator process owned by the test. start() returns once the
// coordinator is serving ("UP ...") or has exited; stop() always waits for it.
class Coordinator {
 public:
  ~Coordinator() { stop(); }
  void start(const std::string& args) {
    stop();
    up_ = false;
    exitCode_ = STILL_ACTIVE;
    lines_.clear();
    port_ = freeLoopbackPort();
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE rd = nullptr;
    HANDLE wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError = wr;
    std::string exe = AH_COORDINATOR_EXE;
    for (auto& ch : exe) if (ch == '/') ch = '\\';
    std::string cmd = "\"" + exe + "\" --port " + std::to_string(port_) + " " + args;
    PROCESS_INFORMATION pi{};
    const BOOL ok = CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr,
                                   &si, &pi);
    CloseHandle(wr);
    if (!ok) { CloseHandle(rd); return; }
    CloseHandle(pi.hThread);
    process_ = pi.hProcess;
    out_ = rd;
    std::string line;
    while (readLine(out_, line)) {
      lines_.push_back(line);
      if (line.rfind("UP ", 0) == 0) { up_ = true; break; }
    }
    if (up_) {
      HANDLE h = out_;
      drain_ = std::thread([h] { std::string l; while (readLine(h, l)) {} });
    } else {
      WaitForSingleObject(process_, INFINITE);
      GetExitCodeProcess(process_, &exitCode_);
    }
  }
  void stop() {
    if (process_) {
      if (up_) TerminateProcess(process_, 0);
      WaitForSingleObject(process_, INFINITE);
      CloseHandle(process_);
      process_ = nullptr;
    }
    if (drain_.joinable()) drain_.join();
    if (out_) { CloseHandle(out_); out_ = nullptr; }
  }
  bool up() const { return up_; }
  DWORD exitCode() const { return exitCode_; }
  std::uint16_t port() const { return port_; }
  std::string output() const {
    std::string s;
    for (const auto& l : lines_) s += l + "\n";
    return s;
  }

 private:
  HANDLE process_ = nullptr;
  HANDLE out_ = nullptr;
  std::thread drain_;
  std::vector<std::string> lines_;
  bool up_ = false;
  DWORD exitCode_ = STILL_ACTIVE;
  std::uint16_t port_ = 0;
};

struct Ack {
  bool ok = false;        // a well-formed ACK arrived
  bool accepted = false;
  std::string msg;
};

class Conn {
 public:
  explicit Conn(std::uint16_t port) { std::string e; open_ = c_.connect("127.0.0.1", port, &e); }
  bool open() const { return open_; }
  Ack request(proto::MessageType t, const wire::Writer& body) {
    Ack a;
    if (!open_) return a;
    proto::Frame f;
    f.type = t;
    f.payload = body.data();
    std::string err;
    if (!net::sendFrame(c_.socketFd(), f, &err)) return a;
    proto::Frame in;
    bool closed = false;
    if (!net::recvFrame(c_.socketFd(), in, closed, &err) || in.type != proto::MessageType::ACK) return a;
    wire::Reader r(in.payload);
    proto::MessageType at = proto::MessageType::ACK;
    a.ok = msg::readAckBody(r, at, a.accepted, a.msg);
    return a;
  }
  Ack registerAs(WorkerId w, WorkerBootId b, std::uint64_t uuid) {
    msg::HelloBody hello;
    hello.node = NodeId{1};
    hello.worker = w;
    hello.boot = b;
    hello.generation = WorkerGeneration{1};
    DeviceIdentity d;
    d.id = AcceleratorId{uuid};
    d.uuid = DeviceUuid{uuid};
    d.name = "synthetic-accelerator";
    d.supported = true;
    return request(proto::MessageType::REGISTER, msg::regBody(hello, {d}));
  }
  Ack observe(const AuthorityEnvelope& env, AcceleratorId id) {
    return request(proto::MessageType::OBSERVATION,
                   msg::obsBody(env, obsFor(id, env.workerId, env.workerBootId, SystemClock{}.now())));
  }
  Ack validate(const AuthorityEnvelope& env, const ValidationRecord& v) {
    return request(proto::MessageType::VALIDATION_RESULT, msg::valBody(env, v));
  }
  Ack fault(const AuthorityEnvelope& env, const Fault& f) {
    return request(proto::MessageType::FAULT_REPORT, msg::faultBody(env, f));
  }
  // Fetches the coordinator's encoded state and decodes it into `into`.
  bool snapshot(HealthStore& into, std::string& err) {
    if (!open_) { err = "not connected"; return false; }
    proto::Frame f;
    f.type = proto::MessageType::SNAPSHOT_REQUEST;
    if (!net::sendFrame(c_.socketFd(), f, &err)) return false;
    proto::Frame in;
    bool closed = false;
    if (!net::recvFrame(c_.socketFd(), in, closed, &err)) return false;
    if (in.type != proto::MessageType::SNAPSHOT_RESPONSE) { err = "unexpected response"; return false; }
    return HealthStore::decode(in.payload, into, &err);
  }

 private:
  net::TcpClient c_;
  bool open_ = false;
};

}  // namespace

// Validation and fault reports are fenced like observations: a superseded
// worker incarnation, a stale coordinator epoch and a replayed validation run
// are refused, and the prior incarnation cannot register again.
AH_TEST(coordinator_fences_reports_and_registrations) {
  if (!g_processTests) return;
  Coordinator co;
  co.start("--epoch 5");
  CHECK_MSG(co.up(), co.output().c_str());
  if (!co.up()) return;
  const WorkerId w{1};
  const AcceleratorId dev{100};
  Conn a(co.port());
  Conn b(co.port());
  CHECK(a.registerAs(w, WorkerBootId{1}, 100).accepted);
  CHECK(a.observe(envFor(5, w, WorkerBootId{1}, 1), dev).accepted);
  CHECK(b.registerAs(w, WorkerBootId{2}, 100).accepted);
  CHECK(b.observe(envFor(5, w, WorkerBootId{2}, 1), dev).accepted);

  const Ack staleVal = a.validate(envFor(5, w, WorkerBootId{1}, 2), fullVal(dev, 1, SystemClock{}.now()));
  CHECK(staleVal.ok && !staleVal.accepted);
  const Ack staleFault = a.fault(envFor(5, w, WorkerBootId{1}, 3), fatalFault(dev, 1, SystemClock{}.now()));
  CHECK(staleFault.ok && !staleFault.accepted);
  const Ack staleEpoch = b.validate(envFor(4, w, WorkerBootId{2}, 2), fullVal(dev, 2, SystemClock{}.now()));
  CHECK(staleEpoch.ok && !staleEpoch.accepted);
  {
    Conn q(co.port());
    HealthStore view(clk(), {}, 0);
    std::string err;
    CHECK_MSG(q.snapshot(view, err), err.c_str());
    CHECK_EQ(view.coordinatorEpoch(), 5u);
    const auto snap = view.snapshot(dev);
    CHECK(snap.validations.empty());
    CHECK_EQ(snap.faultCount, 0u);
    CHECK_EQ(static_cast<int>(snap.state), static_cast<int>(HealthState::HEALTHY));
    CHECK(!snap.latestAssessment.executionReady);
  }

  Conn c(co.port());
  const Ack again = c.registerAs(w, WorkerBootId{1}, 100);
  CHECK(again.ok && !again.accepted);
  CHECK(!c.observe(envFor(5, w, WorkerBootId{1}, 9), dev).accepted);
  CHECK(b.observe(envFor(5, w, WorkerBootId{2}, 2), dev).accepted);

  CHECK(b.validate(envFor(5, w, WorkerBootId{2}, 3), fullVal(dev, 7, SystemClock{}.now())).accepted);
  const Ack replay = b.validate(envFor(5, w, WorkerBootId{2}, 4), fullVal(dev, 7, SystemClock{}.now()));
  CHECK(replay.ok && !replay.accepted);
  {
    Conn q(co.port());
    HealthStore view(clk(), {}, 0);
    std::string err;
    CHECK_MSG(q.snapshot(view, err), err.c_str());
    const auto snap = view.snapshot(dev);
    CHECK_EQ(snap.validations.size(), 1u);
    CHECK(snap.latestAssessment.executionReady);
  }

  // A replayed fault report is refused; the connection stays served.
  CHECK(b.fault(envFor(5, w, WorkerBootId{2}, 5), transientFault(dev, 9, SystemClock{}.now())).accepted);
  const Ack replayFault = b.fault(envFor(5, w, WorkerBootId{2}, 6), transientFault(dev, 9, SystemClock{}.now()));
  CHECK(replayFault.ok && !replayFault.accepted);
  CHECK(b.observe(envFor(5, w, WorkerBootId{2}, 7), dev).accepted);
  co.stop();
}

// A state file that exists but cannot be recovered stops the coordinator
// instead of being replaced by an empty store.
AH_TEST(coordinator_refuses_unrecoverable_state_file) {
  if (!g_processTests) return;
  const std::string p = tempPath("corrupt");
  {
    HealthStore s(clk(), {}, 3);
    const auto id = s.registerDevice(DeviceUuid{300}, NodeId{1});
    s.beginQuarantine(id, QuarantineAuthority::OPERATOR, "operator hold", "operator");
    std::string err;
    CHECK_MSG(s.saveToFile(p, &err), err.c_str());
  }
  auto bytes = readFile(p);
  bytes[bytes.size() / 2] = static_cast<std::uint8_t>(bytes[bytes.size() / 2] ^ 0x5A);
  writeFile(p, bytes);
  Coordinator co;
  co.start("--epoch 3 --state \"" + p + "\" --load");
  CHECK_MSG(!co.up(), "coordinator served in place of an unrecoverable state file");
  CHECK(co.up() || co.exitCode() != 0);
  if (co.up()) {
    Conn q(co.port());
    HealthStore view(clk(), {}, 0);
    std::string err;
    q.snapshot(view, err);  // a snapshot request also saves the state file
  }
  co.stop();
  CHECK_MSG(readFile(p) == bytes, "the unrecoverable state file was overwritten");
  std::remove(p.c_str());
  // No state file yet (first start with --load): the coordinator starts fresh.
  co.start("--epoch 3 --state \"" + p + "\" --load");
  CHECK_MSG(co.up(), co.output().c_str());
  co.stop();
}

// --epoch applies over a loaded state file and never moves the epoch back.
AH_TEST(coordinator_applies_configured_epoch_on_load) {
  if (!g_processTests) return;
  const std::string p = tempPath("epoch");
  {
    HealthStore s(clk(), {}, 2);
    s.registerDevice(DeviceUuid{400}, NodeId{1});
    std::string err;
    CHECK_MSG(s.saveToFile(p, &err), err.c_str());
  }
  const WorkerId w{1};
  const AcceleratorId dev{400};
  Coordinator co;
  co.start("--epoch 3 --state \"" + p + "\" --load --no-save-on-snapshot");
  CHECK_MSG(co.up(), co.output().c_str());
  if (co.up()) {
    Conn a(co.port());
    CHECK(a.registerAs(w, WorkerBootId{1}, 400).accepted);
    CHECK(!a.observe(envFor(2, w, WorkerBootId{1}, 1), dev).accepted);
    CHECK(a.observe(envFor(3, w, WorkerBootId{1}, 2), dev).accepted);
  }
  co.start("--epoch 1 --state \"" + p + "\" --load --no-save-on-snapshot");
  CHECK_MSG(co.up(), co.output().c_str());
  if (co.up()) {
    Conn a(co.port());
    CHECK(a.registerAs(w, WorkerBootId{1}, 400).accepted);
    CHECK(!a.observe(envFor(1, w, WorkerBootId{1}, 1), dev).accepted);
    CHECK(a.observe(envFor(2, w, WorkerBootId{1}, 2), dev).accepted);
  }
  co.stop();
  std::remove(p.c_str());
}
#endif

int main(int argc, char** argv) {
  for (int i = 1; i < argc; ++i) {
    if (std::string(argv[i]) == "--store-only") g_processTests = false;
  }
#ifdef _WIN32
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
#endif
  return testfw::runAll("test_regression");
}
