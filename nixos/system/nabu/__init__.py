"""Nabu web tools for the Home Assistant LLM Assist API."""
from homeassistant.core import HomeAssistant
from homeassistant.config import ConfigType


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    return True