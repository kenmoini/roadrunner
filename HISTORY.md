

## Command Line History

```bash
# Make a directory & enter it
mkdir roadrunner
cd roadrunner

# Init git
git init

# Init golang modules
go mod init github.com/kenmoini/roadrunner

## Add some modules
go get gopkg.in/yaml.v2
go get go.uber.org/zap
go get github.com/mholt/acmez
go get golang.org/x/sys/unix
go get golang.org/x/exp/slices

## Build test
go build

## Run test
./roadrunner

## Commit
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin git@github.com:kenmoini/roadrunner.git
git push -u origin main
```