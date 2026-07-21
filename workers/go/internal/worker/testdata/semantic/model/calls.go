package model

import (
	"fmt"
	"reflect"
)

func ExternalCall(value string) string {
	return fmt.Sprintf("%s", value)
}

func InferredCall[T any](value T) T {
	return value
}

type MethodExpressionTarget struct{}

func (MethodExpressionTarget) Execute() {}

type Executor interface{ Execute() }

type EmbeddedExecutor struct{ Executor }

type FunctionHolder struct{ Functions []func(string) string }

func DirectCallMatrix() {
	local := ExternalCall("local")
	_ = local
	var localVarInit = ExternalCall("local-var")
	_ = localVarInit
	_ = InferredCall(1)
	MethodExpressionTarget{}.Execute()
	MethodExpressionTarget.Execute(MethodExpressionTarget{})
	println(local)
	(func() { ExternalCall("closure") })()

	var dynamic Executor = MethodExpressionTarget{}
	dynamic.Execute()
	embedded := EmbeddedExecutor{Executor: dynamic}
	embedded.Execute()
	functionValue := ExternalCall
	_ = functionValue("dynamic")
	indexedFunctions := []func(string) string{ExternalCall}
	_ = indexedFunctions[0]("indexed")
	holder := FunctionHolder{Functions: indexedFunctions}
	_ = holder.Functions[0]("field-indexed")
	reflect.ValueOf(functionValue).Call(nil)
	_ = string([]byte("conversion"))
}

var PackageInitialized = ExternalCall("package")

func InvokeFunctionType[F ~func()](function F) {
	function()
}

func CycleLeft() {
	CycleRight()
}

func CycleRight() {
	CycleLeft()
}

var ExternalKind = reflect.Invalid
