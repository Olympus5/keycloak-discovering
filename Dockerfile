# syntax=docker/dockerfile:1

FROM quay.io/keycloak/keycloak:latest as build

ADD --chown=keycloak:keycloak --chmod=644 target/keycloak-discovering-1.0.0-SNAPSHOT.jar /opt/keycloak/providers/keycloak-discovering.jar