from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import scripts.nixos_day2_activation as executor

PRIOR = "/nix/store/22222222222222222222222222222222-nixos-system-heim-pc-old"
TARGET = "/nix/store/11111111111111111111111111111111-nixos-system-heim-pc-new"


class RecoveryPreCheckTests(unittest.TestCase):
    def test_no_environment_bypass_for_normal_activation_or_ambient_var(self):
        with patch.dict(os.environ, {"NIXOS_NO_CHECK": "1"}):
            env = executor._minimal_env(TARGET)
        self.assertNotIn("NIXOS_NO_CHECK", env)
        self.assertEqual(env["PATH"], TARGET + "/sw/bin")

    def test_only_verified_recovery_to_prior_closure_bypasses_old_check(self):
        observed = []
        def runner(argv, closure):
            observed.append((list(argv), closure, executor._minimal_env(closure)))
        switch = [PRIOR + "/bin/switch-to-configuration", "switch"]
        with patch.object(executor, "_require_recovery_transaction_state",
                          return_value=(PRIOR, PRIOR)) as transaction, \
             patch.object(executor, "_require_link_target", return_value=PRIOR), \
             patch.object(executor, "_switch_argv", return_value=switch):
            executor._recover(
                prior_closure=PRIOR, target_closure=TARGET, mode="switch",
                runner=runner, profile_may_have_changed=False,
            )
        self.assertGreaterEqual(transaction.call_count, 2)
        self.assertEqual(len(observed), 1)
        argv, closure, env = observed[0]
        self.assertEqual(argv, switch)
        self.assertEqual(closure, PRIOR)
        self.assertEqual(env["NIXOS_NO_CHECK"], "1")
        self.assertEqual(env["PATH"], PRIOR + "/sw/bin")
        self.assertNotIn("NIXOS_NO_CHECK", executor._minimal_env(TARGET))

    def test_bypass_is_reset_even_if_recovery_activation_fails(self):
        def failed_runner(_argv, closure):
            self.assertEqual(closure, PRIOR)
            self.assertEqual(executor._minimal_env(closure)["NIXOS_NO_CHECK"], "1")
            raise executor.RuntimeExecutorError("synthetic old-generation switch failure")
        with patch.object(executor, "_require_recovery_transaction_state",
                          return_value=(PRIOR, PRIOR)), \
             patch.object(executor, "_require_link_target", return_value=PRIOR), \
             patch.object(executor, "_switch_argv",
                          return_value=[PRIOR + "/bin/switch-to-configuration", "switch"]):
            with self.assertRaisesRegex(executor.RuntimeExecutorError,
                                        "synthetic old-generation switch failure"):
                executor._recover(
                    prior_closure=PRIOR, target_closure=TARGET, mode="switch",
                    runner=failed_runner, profile_may_have_changed=False,
                )
        self.assertNotIn("NIXOS_NO_CHECK", executor._minimal_env(TARGET))


if __name__ == "__main__":
    unittest.main()
