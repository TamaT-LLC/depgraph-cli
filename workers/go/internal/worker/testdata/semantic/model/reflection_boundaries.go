package model

import "reflect"

func ReflectionBoundaries(value reflect.Value, typ reflect.Type) {
	value.Call(nil)
	value.CallSlice(nil)
	_ = value.MethodByName("Run")
	_, _ = typ.MethodByName("Run")
	_ = value.FieldByName("Callback")
	_, _ = typ.FieldByName("Callback")
	_ = reflect.MakeFunc(
		reflect.TypeOf(func() {}),
		func([]reflect.Value) []reflect.Value { return nil },
	)
}
