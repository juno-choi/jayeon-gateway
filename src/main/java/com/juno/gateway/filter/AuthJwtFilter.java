package com.juno.gateway.filter;

import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class AuthJwtFilter extends AbstractGatewayFilterFactory<AuthJwtFilter.Config> {
    private Environment env;

    public AuthJwtFilter(Environment env) {
        super(Config.class);
        this.env = env;
    }

    public static class Config{
        //설정에 필요한 내용 정의
    }

    //인증 요청시 확인
    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain)->{
            ServerHttpRequest request = exchange.getRequest();

            if(!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                //헤더에 AUTHORIZATION key 자체가 존재하지 않을 경우
                return onError(exchange, "no AUTHORIZATION header", HttpStatus.UNAUTHORIZED);   //401 반환
            }

            String authorizationHeader = request.getHeaders().get(org.springframework.http.HttpHeaders.AUTHORIZATION).get(0);   //AUTHORIZATION key 값으로 value 가져옴
            String jwt = authorizationHeader.replace("Bearer", ""); //JWT, OAuth는 Bearer로 붙여서 전송하기로 약속함

            if(!isJwtValid(jwt)){
                return onError(exchange, "JWT Token is not valid", HttpStatus.UNAUTHORIZED);
            }

            return chain.filter(exchange);
        });
    }
    //token이 유효한지 확인
    private boolean isJwtValid(String jwt) {
        boolean returnValue = true;


        String subject = null;
        try {
            subject = Jwts.parser().setSigningKey(env.getProperty("token.secret"))  //secret key 값을 통해 parse
                    .parseClaimsJws(jwt).getBody()  //token의 내용을 가져옴
                    .getSubject();
        }catch (Exception e){
            returnValue = false;
        }

        if(subject == null || subject.equals("")){
            returnValue = false;
        }
        return returnValue;
    }

    //에러 발생시 에러 값을 response
    //Mono, Flux -> Spring WebFlux 개념 / 데이터 단위 단일=Mono, 복수=Flux
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error(err);
        return response.setComplete();  //Mono 데이터 return
    }
}
