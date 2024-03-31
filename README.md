# docker-podman-demo(Dummy UBA)

## Purpose
- Demo of running multiple microservices leveraging docker containers & docker-compose
- Demo of running multiple microservices leveraging podman containers & podman-compose
- Demo of creating microservices instances using Docker & Kubernetes
- Demo of creating microservices instances using podman & Kubernetes
- Demo of migrating from Docker to Podman & Orchestrating it through Kubernetes

## Description
There are four microservices in this demo:
1. UBA Accounts Service: Customer Accounts CRUD operations
2. UBA Events Service: Events & Datasource CRUD operations
3. UBA ETL: ETL processing of the events
4. UBA IR: IR Processing of the events

## Collaborate with your team
- [ ] [Git Repository](https://cd.splunkdev.com/sujits/docker-podman-demo)
  - ```git clone git@cd.splunkdev.com:sujits/docker-podman-demo.git```
- [ ] [Docker Images at Docker-Hub](https://hub.docker.com/u/sujits259)
  - https://hub.docker.com/r/sujits259/uba-accounts
  - https://hub.docker.com/r/sujits259/uba-events
  - https://hub.docker.com/r/sujits259/uba-etl
  - https://hub.docker.com/r/sujits259/uba-ir

## Build and Create Docker Images
- To build all modules, goto docker-podman-demo 
  - ```mvn clean package```
- To build individual projects, goto that project(e.g uba-accounts)
  - ```mvn clean package```
- Build docker-image & push to docker hub
  - goto specific project & run 
    - ```./mvnw spring-boot:build-image```
  - Push it to docker hub
    - ```docker push sujits259/uba-ir:1.3```

## Docker-Compose to create containers that run services
#### Docker containers
  - Use local/hub docker image these services to create containers
    - Check all docker images
      - ```docker image ls -a```
    - Check all docker containers
      - ```docker container ls -a```
  - Create and Run docker containers having all the services
    - Goto 'docker-podman-demo' and run
      - ```docker-compose up -d``` (Detached mode)
    - Validate
        - ```docker image ls -a```
        - ```docker container ls -a```
    - Check container logs
      - ```docker container log -f container_id```
    - Stop all running containers
      - ```docker-compose down```
      - ```docker-compose down --rmi all```(Remove all containers/images/resources)

#### Podman Containers
- Pull docker image from docker-hub to create Podman containers
- Use same "docker-compose.yml" file
- Run podman containers having all the services
    - Goto 'docker-podman-demo' and run
        - ```podman-compose up -d```(Detached Mode)
    - Validate
        - ```podman image ls -a```
        - ```podman container ls -a```

#### NOTE: same docker-compose file works seamlessly for both 
- docker-compose up -d
- podman-compose up -d

#### Database: MySQL
- Install "mysqlsh" tool and run following commands
  - ```mysqlsh```
  - ```\s(Status) -> \c(Connect) \c uba-db-user@localhost:3306```
  - ```\sql(SQL Mode) -> show databases; -> \use my_db -> \q:quit```
  - Run any SQL query

## Kubernetes
#### Pods running Docker Containers
 - Goto /docker-podman-demo/k8s directory
   - ```kubectl apply -f prod```
 - Validate
   - ```kubectl get pods/services/pv/pvc/all```
   - ```kubectl get all```
 - Get service URL
   - ```kubectl get services```
   - ```minikube service uba-accounts-node-port-service --url```
 - Get into Pod containers
   - Check containers running in a pod
     - ```kubectl exec -it <pod_name> bash```
#### Database: MySQL
- Execute command/SQL inside MySQL container
    - ```kubectl exec -it <pod_name> bash```
    - ```mysql -h mysqldb -u root -p ```
    - ```use uba-db;```
    - ```show tables;```
    - Run any SQL query

## Kubernetes
#### Pods running Podman Containers
- podman play kube (Need to change the yml)
- OR, podman desktop

## Postman Collection
- Check file under *docker-podman-demo* directory:
  - ```docker-demo.postman_collection.json```

## Authors and acknowledgment
#### Sujit K Singh

## Notes
- uba-accounts & uba-events exit with error
