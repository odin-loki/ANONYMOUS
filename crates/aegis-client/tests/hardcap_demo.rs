//! Hard-cap receiver padding demo (spec §4.3, §11 right-pane analogue for receive).
//!
//! TRUE per-round arrivals spike; OBSERVABLE delivered count stays exactly Q.

use aegis_client::{CountHardCapPadder, HardCapConfig};

#[test]
fn hardcap_demo_observable_flat_under_arrival_spike() {
    let q = 10_u32;
    let mut padder = CountHardCapPadder::new(HardCapConfig::new(q));
    let rounds = 30usize;

    let mut true_arrivals_per_round = Vec::new();
    let mut observable_per_round = Vec::new();

    for r in 0..rounds {
        let arrivals = if (10..18).contains(&r) {
            35 // operational surge: far above Q
        } else if r < 10 {
            2 // quiet
        } else {
            1 // post-spike quiet
        };
        padder.arrive(arrivals);
        true_arrivals_per_round.push(arrivals);

        let out = padder.round_tick();
        observable_per_round.push(out.observable_count());
    }

    // Observable is exactly Q every round — the flat wall on the receive side.
    assert!(observable_per_round.iter().all(|&c| c == q));

    let quiet_mean: f64 = true_arrivals_per_round[..10]
        .iter()
        .map(|&x| x as f64)
        .sum::<f64>()
        / 10.0;
    let spike_mean: f64 = true_arrivals_per_round[10..18]
        .iter()
        .map(|&x| x as f64)
        .sum::<f64>()
        / 8.0;
    let post_mean: f64 = true_arrivals_per_round[18..]
        .iter()
        .map(|&x| x as f64)
        .sum::<f64>()
        / (rounds - 18) as f64;

    println!();
    println!("=== AEGIS hard-cap padding demo (spec §4.3) ===");
    println!("LEFT  — true arrivals per round:");
    println!(
        "        pre-quiet mean={quiet_mean:.1}  SPIKE mean={spike_mean:.1}  post-quiet mean={post_mean:.1}"
    );
    println!("RIGHT — observable deliveries per round (hard-cap Q={q}):");
    println!(
        "        min={} max={} (flat)",
        observable_per_round.iter().min().unwrap(),
        observable_per_round.iter().max().unwrap()
    );
    println!(
        "        deferred backlog after demo={} items (latency cost, not shape leak)",
        padder.backlog()
    );
    println!("Excess arrivals deferred FIFO — observer always sees exactly Q.");
    println!();

    assert!(spike_mean > q as f64 * 2.0, "spike should dominate Q");
    assert!(padder.backlog() > 0, "surge excess must be deferred");
}
