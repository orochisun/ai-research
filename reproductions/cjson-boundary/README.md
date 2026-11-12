# cJSON boundary experiment

The C harness was produced by GPT-6-Luna in a real research task. Fetch the pinned cJSON source with `python3 scripts/fetch_dependencies.py cJSON`, then run `sh reproductions/cjson-boundary/run.sh` from the repository root. Requires clang with ASan/UBSan support.

This harness prints observations for nine cases; it does not assert expected results. A successful exit means only that this bounded execution finished without a sanitizer abort. Independent semantic assertions remain pending. The original target source is linked directly without modifications.
