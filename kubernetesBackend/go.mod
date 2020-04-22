module github.com/oopsie1412/better-blackboard/kubernetesBackend

go 1.13

replace github.com/oopsie1412/better-blackboard/kubernetesBackend/sessions => ./sessions

require (
	github.com/gidoBOSSftw5731/log v0.0.0-20190718204308-3ae037c6203f
	github.com/jinzhu/configor v1.1.1
	github.com/lib/pq v1.4.0
	github.com/oopsie1412/better-blackboard/kubernetesBackend/sessions v0.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.0.0-20200422194213-44a606286825
)
