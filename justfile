# AEGIS dev commands (install `just`, or read these as a cheat-sheet)
sim:            # run the evidence-ledger regression suite
    cd sim && PYTHONPATH=. pytest -q
attack name:    # run a specific original attack script, e.g. `just attack intersection`
    cd sim && PYTHONPATH=. python attacks/{{name}}.py
crypto:         # Phase-2 crypto gate
    cd crates && cargo test -p aegis-crypto
build:
    cd crates && cargo build
