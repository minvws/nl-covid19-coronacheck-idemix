FROM golang

WORKDIR /app

COPY ./ /app

RUN go get ./

CMD ["go", "run", "./", "server", "--listen-address", "0.0.0.0"]
