#!/bin/bash

version=1.0.12
repository=jercle

declare -a imageNames

for dir in ./linux/*/; do
  dir=${dir%*/}
  imageNames=("${imageNames[@]}" "${dir##*/}")
done

printHelp() {
  echo "Usage: ./buildall.sh build|push|prune|gitrel|help"
}

dockerPrune() {
  echo "Pruning docker images and containers"
  docker container prune -f
  docker image prune -a -f
}

buildImages() {
  for imageName in "${imageNames[@]}"; do
    echo -e "Building $repository/$imageName\nTags: latest $version"
    docker build -f ./linux/$imageName/Dockerfile -t $repository/$imageName:latest -t $repository/$imageName:$version --no-cache .
  done
  echo "Done!"
}

pushImages() {
  for imageName in "${imageNames[@]}"; do
    echo "Pushing $repository/$imageName:latest ..."
    docker push $repository/$imageName:latest
    echo "Pushing $repository/$imageName:$version ..."
    docker push $repository/$imageName:$version
  done

  echo "Done!"
}

gitRelease() {

  # echo "git tag -a $version -m Release $version"
  git tag -a $version -m "Release $version"
  git push origin $version
}

if [ "$1" == "build" ]; then
  buildImages
elif [ "$1" == "push" ]; then
  pushImages
elif [ "$1" == "prune" ]; then
  dockerPrune
elif [ "$1" == "gitrel" ]; then
  gitRelease
else
  printHelp
fi
