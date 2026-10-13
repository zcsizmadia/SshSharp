#!/usr/bin/env bash
# Runs the SshSharp vs SSH.NET comparison (tests/SshSharp.Benchmarks, ComparisonBenchmarks and the peak-memory runs) on a Linux machine
# with Docker and the .NET SDK, in parallel lanes. Each lane gets its own OpenSSH container (the CI image, tests/docker) and its own CPU
# cores, split between the client and the server, so lanes do not compete with each other.
#
# Usage, from the repository root on the benchmark machine:
#   scripts/bench-lanes.sh [cores-per-side] [peak-mebibytes]
# needs 14 x cores-per-side cores (7 lanes, client and server each). Results: BenchmarkDotNet.Artifacts/lanes/
set -euo pipefail

CORES=${1:-8}
PEAK_MIB=${2:-1024}
OUT=BenchmarkDotNet.Artifacts/lanes
LANES=(Connect Command Download32MiB ScpUpload32MiB Parallel8 peak:sshsharp peak:sshnet)

needed=$(( ${#LANES[@]} * CORES * 2 ))
if (( needed > $(nproc) )); then
  echo "Needs $needed cores for ${#LANES[@]} lanes x $CORES cores x 2 sides; this machine has $(nproc). Pass fewer cores per side." >&2
  exit 1
fi

docker build -q -t sshsharp-interop --build-arg BASE=alpine:3.22 --build-arg SERVER=openssh tests/docker > /dev/null
dotnet build -c Release tests/SshSharp.Benchmarks -f net10.0 > /dev/null
rm -rf "$OUT"
mkdir -p "$OUT"

pids=()
names=()
for i in "${!LANES[@]}"; do
  lane=${LANES[$i]}
  name="sshsharp-bench-$i"
  first=$((i * CORES * 2))
  client_cpus="$first-$((first + CORES - 1))"
  server_cpus="$((first + CORES))-$((first + 2 * CORES - 1))"
  password=$(openssl rand -hex 16)
  names+=("$name")

  docker rm -f "$name" > /dev/null 2>&1 || true
  # REKEY_LIMIT: the test image renews keys every 32 KiB to exercise rekeying, which would make every transfer crawl.
  # The container's own address, not a published port: Docker's userland proxy would cap the throughput.
  docker run -d --name "$name" --cpuset-cpus "$server_cpus" -e "TEST_PASSWORD=$password" \
    -e "REKEY_LIMIT=default none" sshsharp-interop > /dev/null
  for _ in $(seq 1 30); do
    address=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name")
    if timeout 2 bash -c "exec 3<>/dev/tcp/$address/22 && head -c 4 <&3" 2>/dev/null | grep -q SSH-; then break; fi
    sleep 1
  done

  (
    export SSHSHARP_BENCH_SSHD="$address:22" SSHSHARP_BENCH_USER=sshsharp SSHSHARP_BENCH_PASSWORD="$password"
    if [[ $lane == peak:* ]]; then
      taskset -c "$client_cpus" dotnet run -c Release --no-build --project tests/SshSharp.Benchmarks -f net10.0 -- --peak "${lane#peak:}" "$PEAK_MIB"
    else
      # In-process: the lanes would otherwise rebuild the same projects at the same time.
      taskset -c "$client_cpus" dotnet run -c Release --no-build --project tests/SshSharp.Benchmarks -f net10.0 -- \
        --filter '*ComparisonBenchmarks*' --anyCategories "$lane" --inProcess --artifacts "$OUT/$lane"
    fi
  ) > "$OUT/${lane/:/-}.log" 2>&1 &
  pids+=($!)
  echo "lane $i: $lane (client cores $client_cpus, server cores $server_cpus)"
done

status=0
for pid in "${pids[@]}"; do
  wait "$pid" || status=1
done

docker rm -f "${names[@]}" > /dev/null
for log in "$OUT"/peak-*.log; do tail -n 3 "$log"; done
for report in "$OUT"/*/results/*-report-github.md; do sed -n '/^|/p' "$report"; echo; done
exit $status
