package pcloudbinary

import (
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/rclone/rclone/backend/pcloud/api"
)

var tests = []struct {
	Name         string
	Marshalled   []byte
	Init         any
	Unmarshalled any
	WantErr      error
}{
	{
		Name: "string",
		// msg_len 12, type 111 (short string 100 + str_len), str_len 11, the string
		Marshalled:   []byte{12, 0, 0, 0, 111, 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'},
		Init:         fixtureStringPtr(""),
		Unmarshalled: fixtureStringPtr("hello world"),
	},
	{
		Name: "uint64",
		// msg_len 2, type 8, the number
		Marshalled:   []byte{2, 0, 0, 0, 8, 13},
		Init:         fixtureUint64Ptr(0),
		Unmarshalled: fixtureUint64Ptr(13),
	},
	{
		Name: "int64",
		// msg_len 2, type 8, the number
		Marshalled:   []byte{2, 0, 0, 0, 8, 13},
		Init:         fixtureInt64Ptr(0),
		Unmarshalled: fixtureInt64Ptr(13),
	},
	{
		Name: "int",
		// msg_len 2, type 8, the number
		Marshalled:   []byte{2, 0, 0, 0, 8, 13},
		Init:         fixtureIntPtr(0),
		Unmarshalled: fixtureIntPtr(13),
	},
	{
		Name: "int64 (negative)",
		// msg_len 2, type 8, the number
		Init:         fixtureInt64Ptr(0),
		Unmarshalled: fixtureInt64Ptr(-13),
		WantErr:      NegativeNumberParam,
	},
	{
		Name: "int (negative)",
		// msg_len 2, type 8, the number
		Init:         fixtureIntPtr(0),
		Unmarshalled: fixtureIntPtr(-13),
		WantErr:      NegativeNumberParam,
	},
	{
		Name: "bool(false)",
		// msg_len 1, type 18
		Marshalled:   []byte{1, 0, 0, 0, 18},
		Init:         fixtureBoolPtr(true),
		Unmarshalled: fixtureBoolPtr(false),
	},
	{
		Name: "bool(true)",
		// msg_len 1, type 19
		Marshalled:   []byte{1, 0, 0, 0, 19},
		Init:         fixtureBoolPtr(false),
		Unmarshalled: fixtureBoolPtr(true),
	},
	{
		Name: "time",
		Marshalled: append(
			[]byte{32, 0, 0, 0, 131},                     // msg_len, type short string
			[]byte("Wed, 31 Dec 1969 16:22:17 -0800")..., // the string
		),
		Init: &api.Time{},
		Unmarshalled: func() *api.Time {
			t := api.Time(time.Unix(1337, 0))
			return &t
		}(),
	},
	{
		Name: "array",
		Marshalled: []byte{
			10, 0, 0, 0, 17, // msg_len 11, type 17 (array)
			106, 'n', 'u', 'm', 'b', 'e', 'r', // first element: type 106 (short string, 100 + str_len 6), the string ('number')
			150, // second element: type 150 (re-use string 0)
			255, // delimiter: type 255
		},
		Init:         &[]string{},
		Unmarshalled: &[]string{"number", "number"},
	},
	{
		Name: "struct",
		Marshalled: []byte{
			11, 0, 0, 0, 16, // msg_len 11, type 16 (hash)
			106, 'n', 'u', 'm', 'b', 'e', 'r', // key: type 106 (short string, 100+str_len 6), the string ('number')
			8, 13, // value: type 8 (1 byte number), the number,
			255, // delimiter: type 255
		},
		Init: &struct {
			Number uint64 `json:"number"`
		}{},
		Unmarshalled: &struct {
			Number uint64 `json:"number"`
		}{
			Number: 13,
		},
	},
	{
		Name: "time references",
		Marshalled: []byte{
			46, 0, 0, 0, 16, // msg_len, type 16 (hash)
			104, 'd', 'a', 't', 'e', // key: type 104 (short string), the string "date"
			131, 'M', 'o', 'n', ',', ' ', '0', '2', ' ', 'J', 'a', 'n', ' ', '2', '0', '0', '6', ' ', '1', '5', ':', '0', '4', ':', '0', '5', ' ', '-', '0', '7', '0', '0', // value: type 131 (short string), a valid datetime
			105, 'd', 'a', 't', 'e', '2', // key: type 105 (short string), the string "date2"
			151, // value: type 151 (reuse string 1, "date")
			255, // delimiter: type 255
		},
		Init: &struct {
			Date  api.Time `json:"date"`
			Date2 api.Time `json:"date2"`
		}{},
		Unmarshalled: &struct {
			Date  api.Time `json:"date"`
			Date2 api.Time `json:"date2"`
		}{
			Date: func() api.Time {
				t, _ := time.Parse(timeFormat, "Mon, 02 Jan 2006 15:04:05 -0700")
				return api.Time(t)
			}(),
			Date2: func() api.Time {
				t, _ := time.Parse(timeFormat, "Mon, 02 Jan 2006 15:04:05 -0700")
				return api.Time(t)
			}(),
		},
	},
	{
		Name: "itemresult",
		Marshalled: []byte{
			// actual result received by API
			33, 0, 0, 0, 16, 106, 114, 101, 115, 117, 108, 116, 9, 208, 7, 105, 101, 114, 114, 111, 114, 114, 76, 111, 103, 32, 105, 110, 32, 102, 97, 105, 108, 101, 100, 46, 255,
		},
		Init: &api.ItemResult{},
		Unmarshalled: &api.ItemResult{
			Error: api.Error{
				ErrorString: "Log in failed.",
				Result:      2000,
			},
		},
	},
}

func TestUnmarshal(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			if tt.Marshalled == nil {
				t.Skip("unmarshalled was empty - nothing to handle.")
			}
			err := Unmarshal(tt.Marshalled, tt.Init)
			if !errors.Is(err, tt.WantErr) {
				t.Fatalf("gotErr %s, wantErr %s", err, tt.WantErr)
			}
			if diff := cmp.Diff(tt.Init, tt.Unmarshalled, cmpopts.EquateComparable(api.Time{})); diff != "" {
				t.Errorf("got != want, diff: %s", diff)
			}
		})
	}
}

func TestMarshal(t *testing.T) {
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			got, err := Marshal(tt.Unmarshalled)
			if !errors.Is(err, tt.WantErr) {
				t.Fatalf("gotErr %s, wantErr %s", err, tt.WantErr)
			}
			if diff := cmp.Diff(got, tt.Marshalled); diff != "" {
				t.Errorf("got != want\ngot (%d): %d\nwant (%d):%d", len(got), got, len(tt.Marshalled), tt.Marshalled)
			}
		})
	}
}

func fixtureStringPtr(s string) *string {
	return &s
}

func fixtureUint64Ptr(n uint64) *uint64 {
	return &n
}

func fixtureInt64Ptr(n int64) *int64 {
	return &n
}

func fixtureIntPtr(n int) *int {
	return &n
}

func fixtureBoolPtr(b bool) *bool {
	return &b
}

/*
func TestResponseMarshall(t *testing.T) {
	tests := []struct {
		Name    string
		Obj     BinaryResponse
		WantErr error
	}{
		{
			Name: "valid",
			Obj: BinaryResponse{
				Values: map[string]any{
					"shortString":   "s1",
					"repeatedShort": "s1",
					"longStr":       "asdfasdflkjlkewjrlasdflkasndflaskdflkasjfdlkajfwiejf3",
					"number":        1,
					"longNumber":    987654321123456789,
					"nested": map[string]any{
						"bool":  true,
						"bool2": false,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			buf := bytes.NewBuffer([]byte{})
			inN, err := tt.Obj.WriteTo(buf)
			if err != tt.WantErr {
				t.Errorf("gotErr: %s, wantErr: %s", err, tt.WantErr)
			}
			gotBytes := buf.Bytes()
			GotObj := BinaryResponse{}
			outN, err := GotObj.Read(gotBytes)
			if err != tt.WantErr {
				t.Errorf("gotErr: %s, wantErr: %s", err, tt.WantErr)
			}
			if inN != outN {
				t.Errorf("inN (%d) != outN (%d)", inN, outN)
			}
			t.Errorf("got %v, want %v", GotObj, tt.Obj)
		})
	}
}
*/
