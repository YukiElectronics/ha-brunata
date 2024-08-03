"""Sensor platform for Brunata Online."""

from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass
from homeassistant.const import UnitOfEnergy, UnitOfVolume

from .const import DEFAULT_NAME, DOMAIN, ICON, SENSOR
from .entity import BrunataOnlineEntity


async def async_setup_entry(hass, entry, async_add_devices):
    """Setup sensor platform."""
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_devices(
        [
            BrunataOnlineEnergySensor(coordinator, entry),
            BrunataOnlineWaterSensor(coordinator, entry),
            BrunataOnlineHeatingSensor(coordinator, entry),
        ]
    )


class BrunataOnlineEnergySensor(BrunataOnlineEntity):
    """Energy Sensor"""

    _attr_name = "Brunata Energy Consumed"
    _attr_native_unit_of_measurement = UnitOfEnergy
    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_state_class = SensorStateClass.TOTAL_INCREASING

    @property
    def name(self):
        """Return the name of the sensor."""
        return f"{DEFAULT_NAME}_{SENSOR}"

    @property
    def state(self):
        """Return the state of the sensor."""
        return self.coordinator.data.get("body")

    @property
    def icon(self):
        """Return the icon of the sensor."""
        return ICON

    @property
    def device_class(self):
        """Return the device class of the sensor."""
        return "brunata_online__custom_device_class"


class BrunataOnlineWaterSensor(BrunataOnlineEntity):
    """brunata_online Sensor class."""

    _attr_name = "Brunata Water Consumed"
    _attr_native_unit_of_measurement = UnitOfVolume
    _attr_device_class = SensorDeviceClass.VOLUME
    _attr_state_class = SensorStateClass.TOTAL_INCREASING

    @property
    def name(self):
        """Return the name of the sensor."""
        return f"{DEFAULT_NAME}_{SENSOR}"

    @property
    def state(self):
        """Return the state of the sensor."""
        return self.coordinator.data.get("body")

    @property
    def icon(self):
        """Return the icon of the sensor."""
        return ICON

    @property
    def device_class(self):
        """Return the device class of the sensor."""
        return "brunata_online__custom_device_class"


class BrunataOnlineHeatingSensor(BrunataOnlineEntity):
    """brunata_online Sensor class."""

    _attr_name = "Brunata Energy Consumed"
    _attr_native_unit_of_measurement = UnitOfEnergy
    _attr_device_class = SensorDeviceClass.ENERGY
    _attr_state_class = SensorStateClass.TOTAL_INCREASING

    @property
    def name(self):
        """Return the name of the sensor."""
        return f"{DEFAULT_NAME}_{SENSOR}"

    @property
    def state(self):
        """Return the state of the sensor."""
        return self.coordinator.data.get("body")

    @property
    def icon(self):
        """Return the icon of the sensor."""
        return ICON

    @property
    def device_class(self):
        """Return the device class of the sensor."""
        return "brunata_online__custom_device_class"
