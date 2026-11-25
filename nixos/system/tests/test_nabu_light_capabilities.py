"""Capability-aware HassLightSet tests without requiring Home Assistant."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from unittest import IsolatedAsyncioTestCase, mock
import importlib.util
import sys


SOURCE = Path(__file__).resolve().parents[1] / "nabu" / "__init__.py"


@dataclass
class Match:
    states: list
    areas: tuple = ()


class Response:
    def __init__(self):
        self.success_results = []
        self.failed_results = []
        self.error = None
        self.speech = None

    def async_set_error(self, code, speech):
        self.error, self.speech = code, speech

    def async_set_results(self, successes, failures):
        self.success_results, self.failed_results = successes, failures

    def async_set_speech(self, speech):
        self.speech = speech


class Handler:
    def __init__(self, intent_type, domain, service, **kwargs):
        self.intent_type, self.domain, self.service = intent_type, domain, service
        vars(self).update(kwargs)

    async def async_handle_states(self, obj, match, constraints, preferences=None):
        obj.called.extend(s.entity_id for s in match.states)
        response = obj.create_response()
        response.success_results = [s.entity_id for s in match.states]
        return response


def state(entity, modes):
    return SimpleNamespace(entity_id=entity, name=entity,
                           attributes={"supported_color_modes": modes})


class LightCapabilitiesTests(IsolatedAsyncioTestCase):
    def setUp(self):
        self.original = Handler(
            "HassLightSet", "light", "turn_on", required_slots={},
            optional_slots={"color": object()}, required_domains={"light"},
            required_features=None, required_states=None,
            description="original schema", platforms={"light"}, device_classes=None,
        )
        self.handlers = [self.original]
        self.register = mock.Mock(side_effect=lambda hass, handler: self.handlers.__setitem__(0, handler))
        fake_intent = SimpleNamespace(
            ServiceIntentHandler=Handler, async_get=lambda hass: self.handlers,
            async_register=self.register,
            IntentResponseErrorCode=SimpleNamespace(FAILED_TO_HANDLE="failed_to_handle"),
            IntentResponseTargetType=SimpleNamespace(ENTITY="entity"),
            IntentResponseTarget=lambda **kwargs: SimpleNamespace(**kwargs),
        )
        self.on_started = mock.Mock()
        modules = {
            "homeassistant": SimpleNamespace(),
            "homeassistant.config": SimpleNamespace(ConfigType=dict),
            "homeassistant.core": SimpleNamespace(HomeAssistant=object, callback=lambda f: f),
            "homeassistant.helpers": SimpleNamespace(intent=fake_intent),
            "homeassistant.helpers.start": SimpleNamespace(async_at_started=self.on_started),
        }
        spec = importlib.util.spec_from_file_location("nabu_light_capability_candidate", SOURCE)
        self.module = importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules, modules):
            spec.loader.exec_module(self.module)
        self.hass = object()

    def installed(self):
        self.assertTrue(self.module.register_capability_aware_light_intent(self.hass))
        return self.handlers[0]

    def request(self, **slots):
        return SimpleNamespace(slots=slots, language="de", called=[],
                               create_response=Response)

    async def test_color_only_laser_is_not_turned_on(self):
        h = self.installed()
        obj = self.request(color={"value": (0, 0, 255)})
        result = await h.async_handle_states(obj, Match([state("laser", ["brightness"])]), None)
        self.assertEqual(obj.called, [])
        self.assertEqual(result.error, "failed_to_handle")
        self.assertIn("unterstützt", result.speech)

    async def test_temperature_plus_brightness_cannot_be_partially_applied_to_laser(self):
        h = self.installed()
        obj = self.request(temperature={"value": 3000}, brightness={"value": 50})
        result = await h.async_handle_states(obj, Match([state("laser", ["brightness"])]), None)
        self.assertEqual(obj.called, [])
        self.assertEqual(result.error, "failed_to_handle")

    async def test_laser_brightness_and_background_color_still_dispatch(self):
        h = self.installed()
        for name, modes, slots in [
            ("laser", ["brightness"], {"brightness": {"value": 50}}),
            ("background", ["hs", "white"], {"color": {"value": (0, 0, 255)}}),
            ("ct", ["color_temp"], {"color": {"value": (0, 0, 255)}}),
            ("rgb", ["rgb"], {"temperature": {"value": 3000}}),
        ]:
            with self.subTest(name=name):
                obj = self.request(**slots)
                result = await h.async_handle_states(obj, Match([state(name, modes)]), None)
                self.assertEqual(obj.called, [name])
                self.assertIsNone(result.error)

    async def test_room_with_mixed_capabilities_reports_partial_dispatch(self):
        h = self.installed()
        obj = self.request(color={"value": (0, 0, 255)})
        original = Match([state("laser", ["brightness"]), state("rgb", ["rgb"])], ("room",))
        result = await h.async_handle_states(obj, original, None)
        self.assertEqual(obj.called, ["rgb"])
        self.assertEqual([x.id for x in result.failed_results], ["laser"])
        self.assertEqual(len(original.states), 2)
        self.assertIn("nur", result.speech)

    async def test_onoff_only_cannot_be_dimmed(self):
        h = self.installed()
        obj = self.request(brightness={"value": 50})
        result = await h.async_handle_states(obj, Match([state("switchlight", ["onoff"])]), None)
        self.assertEqual(obj.called, [])
        self.assertEqual(result.error, "failed_to_handle")

    async def test_zero_brightness_preserves_upstream_turn_off(self):
        h = self.installed()
        obj = self.request(brightness={"value": 0})
        result = await h.async_handle_states(obj, Match([state("switchlight", ["onoff"])]), None)
        self.assertEqual(obj.called, ["switchlight"])
        self.assertIsNone(result.error)

    async def test_unknown_capabilities_keep_upstream_semantics(self):
        h = self.installed()
        for modes in (None, [], ["unknown"], ["future_mode"]):
            obj = self.request(color={"value": (0, 0, 255)})
            await h.async_handle_states(obj, Match([state("unknown", modes)]), None)
            self.assertEqual(obj.called, ["unknown"])

    def test_registration_preserves_handler_contract_and_is_idempotent(self):
        h = self.installed()
        self.assertEqual(h.optional_slots, self.original.optional_slots)
        self.assertEqual(h.description, self.original.description)
        self.assertEqual(h.required_domains, self.original.required_domains)
        self.assertEqual(h.platforms, self.original.platforms)
        self.assertTrue(self.module.register_capability_aware_light_intent(self.hass))
        self.assertEqual(self.register.call_count, 1)

    async def test_setup_schedules_registration_after_ha_start(self):
        self.assertTrue(await self.module.async_setup(self.hass, {}))
        self.on_started.assert_called_once()
        self.assertIs(self.handlers[0], self.original)
        self.on_started.call_args.args[1](self.hass)
        self.assertIsInstance(self.handlers[0], self.module.CapabilityAwareLightSet)

    def test_unrecognized_upstream_handler_not_replaced(self):
        self.handlers[0] = SimpleNamespace(intent_type="HassLightSet")
        self.assertFalse(self.module.register_capability_aware_light_intent(self.hass))
        self.register.assert_not_called()
