package caps

type Capability interface {
	capability()
}

type capabilityMarker struct{}

func (capabilityMarker) capability() {}
