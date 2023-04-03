package persistence

import (
	"errors"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/google/uuid"
)

// InMemoryDeviceRepository is an in-memory implementation of the DeviceRepository interface.
type InMemoryDeviceRepository struct {
	devices map[uuid.UUID]*domain.Device
}

// NewInMemoryDeviceRepository creates a new instance of InMemoryDeviceRepository.
func NewInMemoryDeviceRepository() *InMemoryDeviceRepository {
	return &InMemoryDeviceRepository{
		devices: make(map[uuid.UUID]*domain.Device),
	}
}

// Save saves a new device to the repository.
func (r *InMemoryDeviceRepository) Save(device *domain.Device) error {
	if _, ok := r.devices[device.ID]; ok {
		return errors.New("device already exists")
	}
	r.devices[device.ID] = device
	return nil
}

// FindByID finds a device by ID in the repository.
func (r *InMemoryDeviceRepository) FindByID(id uuid.UUID) (*domain.Device, error) {
	device, ok := r.devices[id]
	if !ok {
		return nil, errors.New("device not found")
	}

	return device, nil
}

// FindAll returns all devices in the repository.
func (r *InMemoryDeviceRepository) FindAll() ([]*domain.Device, error) {
	devices := make([]*domain.Device, 0, len(r.devices))
	for _, device := range r.devices {
		devices = append(devices, device)
	}

	return devices, nil
}
