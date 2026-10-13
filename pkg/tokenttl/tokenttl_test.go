package tokenttl

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	assert.Equal(t, Default, parse(""))
	assert.Equal(t, 8760*time.Hour, parse("8760h"))
	for _, bad := range []string{"abc", "30d", "0s", "-5h", "999999h"} {
		assert.Equal(t, Default, parse(bad), bad)
	}
}
