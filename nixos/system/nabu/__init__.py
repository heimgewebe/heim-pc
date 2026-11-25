"""Nabu web tools and native Assist capability checks."""
from dataclasses import replace
import logging

from homeassistant.config import ConfigType
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import intent
from homeassistant.helpers.start import async_at_started

_LOGGER = logging.getLogger(__name__)

# HA converts RGB to a supported colour space (including colour temperature),
# and can emulate temperature on colour-capable lights. Preserve that behaviour.
_COLOR_OR_TEMP_MODES = frozenset({"hs", "xy", "rgb", "rgbw", "rgbww", "color_temp"})
_KNOWN_MODES = _COLOR_OR_TEMP_MODES | {"onoff", "brightness", "white"}


def unsupported_light_setting(slots, modes):
    """Reject only a known capability mismatch; retain unknown/future modes."""
    if not isinstance(modes, (list, tuple, set, frozenset)) or not modes:
        return False
    if any(not isinstance(mode, str) for mode in modes):
        return False
    modes = set(modes)
    if not modes <= _KNOWN_MODES:
        return False
    if ("color" in slots or "temperature" in slots) and not modes & _COLOR_OR_TEMP_MODES:
        return True
    # HA treats brightness zero as an explicit turn-off even on on/off lights.
    return ("brightness" in slots and modes == {"onoff"}
            and slots["brightness"]["value"] != 0)


class CapabilityAwareLightSet(intent.ServiceIntentHandler):
    """Keep HA matching and service handling; skip known incompatible targets."""

    async def async_handle_states(
        self, intent_obj, match_result, match_constraints, match_preferences=None
    ):
        supported, unsupported = [], []
        for state in match_result.states:
            targets = (unsupported if unsupported_light_setting(
                intent_obj.slots, state.attributes.get("supported_color_modes")
            ) else supported)
            targets.append(state)

        if not unsupported:
            return await super().async_handle_states(
                intent_obj, match_result, match_constraints, match_preferences
            )

        german = intent_obj.language.split("-")[0].lower() == "de"
        if not supported:
            response = intent_obj.create_response()
            response.async_set_error(
                intent.IntentResponseErrorCode.FAILED_TO_HANDLE,
                ("Das ausgewählte Licht unterstützt diese Einstellung nicht."
                 if len(unsupported) == 1 else
                 "Die ausgewählten Lichter unterstützen diese Einstellung nicht.")
                if german else "The selected lights do not support that setting.",
            )
            return response

        # Do not mutate the upstream match result or split a combined request
        # into incompatible partial operations on an individual light.
        response = await super().async_handle_states(
            intent_obj, replace(match_result, states=supported),
            match_constraints, match_preferences
        )
        response.async_set_results(response.success_results, response.failed_results + [
            intent.IntentResponseTarget(
                type=intent.IntentResponseTargetType.ENTITY,
                name=state.name, id=state.entity_id,
            )
            for state in unsupported
        ])
        response.async_set_speech(
            "Ich habe den Auftrag nur an passende Lichter gesendet. Die anderen unterstützen diese Einstellung nicht."
            if german else
            "I sent the request only to compatible lights. The others do not support that setting."
        )
        return response


def register_capability_aware_light_intent(hass: HomeAssistant) -> bool:
    """Replace only the known HA handler, retaining its original tool schema."""
    original = next(
        (handler for handler in intent.async_get(hass) if handler.intent_type == "HassLightSet"),
        None,
    )
    if isinstance(original, CapabilityAwareLightSet):
        return True
    if (type(original) is not intent.ServiceIntentHandler
            or original.domain != "light" or original.service != "turn_on"):
        return False
    try:
        replacement = CapabilityAwareLightSet(
            original.intent_type, original.domain, original.service,
            required_slots=original.required_slots, optional_slots=original.optional_slots,
            required_domains=original.required_domains, required_features=original.required_features,
            required_states=original.required_states, description=original.description,
            platforms=original.platforms, device_classes=original.device_classes,
        )
    except (AttributeError, TypeError):
        # A newer or customized HA handler may have its own capability logic.
        # Preserve it instead of preventing HA startup.
        return False
    intent.async_register(hass, replacement)
    return True


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    @callback
    def register_after_start(started_hass):
        if not register_capability_aware_light_intent(started_hass):
            _LOGGER.warning("Nabu: compatible HassLightSet handler not found; capability guard not installed")

    async_at_started(hass, register_after_start)
    return True
