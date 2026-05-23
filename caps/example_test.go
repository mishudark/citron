package caps

import "strings"

import "fmt"

func ExampleClassify() {
	secret := Classify("my-secret-api-key")
	fmt.Println(secret)
	// Output: Classified(****)
}

func ExampleMap() {
	secret := Classify("hello world")
	upper := Map(secret, func(s string) string {
		var result strings.Builder
		for _, ch := range s {
			if ch >= 'a' && ch <= 'z' {
				result.WriteString(string(ch - 32))
			} else {
				result.WriteString(string(ch))
			}
		}
		return result.String()
	})
	fmt.Println(upper)
	// Output: Classified(****)
}

func ExampleFlatMap() {
	secret := Classify(42)
	result := FlatMap(secret, func(v int) Classified[string] {
		return Classify(fmt.Sprintf("the answer is %d", v))
	})
	fmt.Println(result)
	// Output: Classified(****)
}

func ExampleNewIOCapability() {
	io := NewIOCapability(nil, nil)
	io.Println("hello from citron")
	// Output: hello from citron
}

func ExampleClassified_String() {
	c := Classify("sensitive-data")
	fmt.Println(c.String())
	// Output: Classified(****)
}

func ExampleRequestVirtualFileSystem() {
	vfs := NewVirtualFileSystem()
	vfs.Set("/work/hello.txt", "Hello, World!")

	_, _ = RequestVirtualFileSystem[any]("/work", vfs, nil, func(fs FileSystem) (any, error) {
		entry, _ := fs.Access("hello.txt")
		content, _ := entry.Read()
		fmt.Println(content)
		return nil, nil
	})
	// Output: Hello, World!
}

func ExampleFileSystem_scope() {
	vfs := NewVirtualFileSystem()

	var leaked FileSystem
	_, _ = RequestVirtualFileSystem[any]("/work", vfs, nil, func(fs FileSystem) (any, error) {
		leaked = fs
		return nil, nil
	})

	_, err := leaked.Access("test.txt")
	fmt.Println(err != nil)
	// Output: true
}
