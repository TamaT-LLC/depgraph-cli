module example.com/app

go 1.23

require (
	example.com/shared v0.0.0
	example.com/old v1.2.3
	example.net/external v1.0.0 // indirect
)

replace example.com/shared => ../shared
