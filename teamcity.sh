#!/bin/bash -eu
curl https://github.emcrubicon.com/raw/coreservices/coreservices-deploy/master/version.sh -u $GIT_TOKEN:x-oauth-basic -sSfO
source version.sh
curl https://github.emcrubicon.com/raw/coreservices/coreservices-deploy/master/download-helm.sh -u $GIT_TOKEN:x-oauth-basic -sSfO
source download-helm.sh
curl https://github.emcrubicon.com/raw/coreservices/coreservices-deploy/master/download-yq.sh -u $GIT_TOKEN:x-oauth-basic -sSfO
source download-yq.sh
docker login -u teamcity -p $ART_API_KEY $DOCKER_REPO

# Maven package
export PATH=$TOOL_MAVEN/bin:$PATH
mkdir $HOME/.m2
export MAVEN_OPTS=-Duser.home=$HOME
mvn -B versions:set -DnewVersion=$VERSION
mvn -B clean package
echo "##teamcity[importData type='surefire' path='target/surefire-reports/*.xml']"

# JaCoCO TODO
# +:**/classes/**/*.class
# -:**/test-classes/**/*.class
# +:com.virtustream.coreservices.rolodex.*

# Move JAR
ARTIFACT=rolodex-$VERSION.jar
cp $HOME/target/$ARTIFACT $HOME/src/main/docker

# Build Docker Image
docker build \
    -t $DOCKER_REPO/coreservices/rolodex:$VERSION \
    -t $DOCKER_REPO/coreservices/rolodex:latest \
    --build-arg ARTIFACT=$ARTIFACT \
    $HOME/src/main/docker/.

docker push $DOCKER_REPO/coreservices/rolodex:$VERSION
if [ "$REPO_TAG" = "true" ]; then
    docker tag $DOCKER_REPO/coreservices/rolodex:$VERSION $DOCKER_REPO/coreservices/rolodex:latest
    docker push $DOCKER_REPO/coreservices/rolodex:latest
fi

# push helm
cd $HOME/HelmCharts
helm init -c
helm repo add $HELM_REPO $HELM_REPO_URL
helm repo add core-helm-local $ART_URL/core-helm-local # TODO remove
helm dep up rolodex
yq w -i rolodex/values.yaml image.tag $VERSION
yq w -i rolodex/values.yaml image.repository $DOCKER_REPO/coreservices/rolodex
yq w -i rolodex/Chart.yaml version $VERSION
helm package rolodex --save=false
file=rolodex-$VERSION.tgz
curl -T $file $HELM_REPO_URL/$file -uteamcity:$ART_API_KEY -sSf