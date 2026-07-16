package model

type Input struct {
	Value string
}

type Output struct {
	Value string
}

type Worker interface {
	Work(Input) Output
}

type Resettable interface {
	Worker
	Reset()
}

type Service struct{}

func (Service) Work(input Input) Output {
	return Output{Value: input.Value}
}

func (Service) Reset() {}

func (*Service) Close() {}

type Pair[A, B any] struct {
	First  A
	Second B
}

func Convert[A, B any](value A, convert func(A) B) B {
	return convert(value)
}

func outputToInput(value Output) Input {
	return Input{Value: value.Value}
}

func Build(input Input) Pair[Output, Input] {
	output := Service{}.Work(input)
	converted := Convert[Output, Input](output, outputToInput)
	return Pair[Output, Input]{First: output, Second: converted}
}

var Default Worker = Service{}
var ResettableDefault Resettable = Service{}

type WorkerAlias = Worker

type AliasResettable interface {
	WorkerAlias
}

type Nested struct {
	Inner struct {
		Ghost int
	}
	Contract interface {
		Phantom()
	}
}

var _ Worker = Service{}

func init() {}
func init() {}

func GenericScopeA[T any]() { _ = Convert[T, T] }
func GenericScopeB[T any]() { _ = Convert[T, T] }

type Getter[T any] struct{ Value T }

func (getter Getter[T]) Get() T { return getter.Value }

type IntGetter interface{ Get() int }

var _ IntGetter = Getter[int]{}

type FuncBox[T any] struct{}

var FuncA FuncBox[func(x int)]
var FuncB FuncBox[func(y int)]

type InterfaceBox[T any] struct{}

var DirectInterface InterfaceBox[interface{ Get() int }]
var EmbeddedInterface InterfaceBox[interface{ IntGetter }]

type GenericMatcher[T any] struct{}

func (GenericMatcher[T]) Match(T) {}

type GenericMatch[T any] interface{ Match(T) }

var GenericMatchValue GenericMatch[int] = GenericMatcher[int]{}

type ScopedBox[T any] struct{}

func (ScopedBox[T]) Scoped(T) {}

type ScopedContract[T any] interface{ Scoped(T) }

func ScopedF[T any]() {
	var _ ScopedContract[T] = ScopedBox[T]{}
}

func ScopedG[T any]() {
	var _ ScopedContract[T] = ScopedBox[T]{}
}
