package pcloudbinary

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

type RequestTestCase struct {
	Name       string
	Obj        BinaryRequest
	Marshalled []byte
	WantErr    error
}

func fixtureRequestTestCases(t *testing.T) []RequestTestCase {
	return []RequestTestCase{
		{
			Name: "valid",
			Marshalled: appendAll(t,
				100, 0, // req len
				8, "methodXy", // method len, method
				4,           // num param
				0|3,         // string param, name len 3
				"sp1",       // param name
				60, 0, 0, 0, // param value len
				`hello? sausage/êé/Hello, 世界/ " ' @ < > & ? + ≠/z.txt`, // param value
				64|3,                     // num param, name len 3
				"np2",                    // param name
				123, 0, 0, 0, 0, 0, 0, 0, // 8 byte number
				128|3, // bool param, name len 3
				"bp2", // param name
				1,     // value != 0 > true
				128|3, // bool param, name len 3
				"bp1", // param name
				0,     // value == 0 > false
			),
			Obj: BinaryRequest{
				Method: "methodXy",
				StringParams: map[string]string{
					"sp1": `hello? sausage/êé/Hello, 世界/ " ' @ < > & ? + ≠/z.txt`,
				},
				NumParams: map[string]uint64{
					"np2": 123,
				},
				BoolParams: map[string]bool{
					"bp2": true,
					"bp1": false,
				},
			},
		},
	}
}

func appendAll(t *testing.T, bs ...any) []byte {
	t.Helper()
	r := []byte{}
	for _, b := range bs {
		switch c := b.(type) {
		case []byte:
			r = append(r, c...)
		case string:
			r = append(r, []byte(c)...)
		case byte:
			r = append(r, c)
		case int:
			r = append(r, byte(c))
		default:
			t.Fatalf("setup test: unsupported byte type: %v", b)
		}
	}
	return r
}

func TestRequestMarshall(t *testing.T) {
	for _, tt := range fixtureRequestTestCases(t) {
		t.Run(tt.Name, func(t *testing.T) {
			gotBytes, err := tt.Obj.Marshal()
			if err != tt.WantErr {
				t.Errorf("gotErr: %s, wantErr: %s", err, tt.WantErr)
			}

			inN := len(tt.Marshalled)
			outN := len(gotBytes)
			if inN != outN {
				t.Errorf("inN (%d) != outN (%d)", inN, outN)
			}
			if diff := cmp.Diff(gotBytes, tt.Marshalled); diff != "" {
				t.Errorf("got != want\ngot: %d\nwant:%d", gotBytes, tt.Marshalled)
			}
		})
	}
}

func TestRequestUnmarshall(t *testing.T) {
	for _, tt := range fixtureRequestTestCases(t) {
		t.Run(tt.Name, func(t *testing.T) {
			gotObj := BinaryRequest{}
			outN, err := gotObj.Read(tt.Marshalled)
			if err != tt.WantErr {
				t.Errorf("gotErr: %s, wantErr: %s", err, tt.WantErr)
			}

			inN := int64(len(tt.Marshalled))
			if inN != outN {
				t.Errorf("inN (%d) != outN (%d)", inN, outN)
			}
			if diff := cmp.Diff(gotObj, tt.Obj); diff != "" {
				t.Errorf("got != want, diff: %s", diff)
			}
		})
	}
}
