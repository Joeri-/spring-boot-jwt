# README

## build

```
$ mvn clean package
```

## run

```
$ mvn spring-boot:run
```

## functionality
Using HTTPie as a command line HTTP client

Sign up a new user
```
$ http POST localhost:8080/sign-in username=admin password=password -v
```

Log in the new user (and get a new JWT)
```
$ http POST localhost:8080/login username=admin password=password -v
```

Access authenticated resource
```
$ http http://localhost:8080/users Authentication:"Bearer xxx.yyy.zzz"
```
