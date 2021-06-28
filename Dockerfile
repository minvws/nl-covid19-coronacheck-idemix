FROM golang

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN go get ./

COPY ./ /app

CMD ["go", "run", "./", "server", "--listen-address", "0.0.0.0"]
