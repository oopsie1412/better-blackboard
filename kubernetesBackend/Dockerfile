# Get latest golang docker image.
FROM golang:1.13.5

# Create a directory inside the container to store our web-app and then make it working directory.
RUN mkdir -p /go/src/betterbb
WORKDIR /go/src/betterbb
#RUN go get github.com/codegangsta/gin

# Copy the web-app directory into the container.
COPY . /go/src/betterbb
COPY ./config.yml /go/src/betterbb

RUN go build kubernetesBackend.go


# Expose port 9001 to the host so that nginx can access your application
EXPOSE 9001
 

ENV PORT 9001

# Tell Docker what command to run when the container starts
#CMD gin run
CMD ./kubernetesBackend