# springSecurityOauth2Guide

### 이 가이드는 delight 프로젝트를 진행하면서 작성한 security oauth2 코드에 대한 설명과 이유, 이해를 바탕으로 하고 있습니다.

jwt 와 security 에서 제공하는 yml 파일 형식의 인증을 따르고 있습니다.       

저의 Oauth2 security 는 크게 5가지로 설정하였습니다.

목차
* Security config
* `http.addFilterBefore();`
* `http.oauth2Login().successHandler();`
* `http.oauth2Login().failureHandler();`
* `http.userInfoEndpoint().userService();`


### Security config

   <details>
   <summary>
   WebSecurityConfigurerAdapter
   </summary>
   <br>

   ```java
   /**
    * @Created by Doe
    * @Date: 2021/07/29
    */
   
   @RequiredArgsConstructor
   @EnableWebSecurity
   public class SecurityConfig extends WebSecurityConfigurerAdapter {
   
       private final CustomOAuth2UserService customOAuth2UserService;
       private final JWTAuthenticationFilter jwtAuthenticationFilter;
       private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
       private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
   
       @Override
       protected void configure(HttpSecurity http) throws Exception {
           
           http.csrf().disable()
                   .authorizeRequests().antMatchers("/", "/h2-console").permitAll()
                   .antMatchers("/restricted").authenticated();
   
           http.addFilterBefore(jwtAuthenticationFilter, BasicAuthenticationFilter.class);
           
           http.oauth2Login()
                   .successHandler(customAuthenticationSuccessHandler)
                   .failureHandler(customAuthenticationFailureHandler)
                   .userInfoEndpoint().userService(customOAuth2UserService);
       }
   }
   ```
   <br>

   이 구조를 간단하게 설명해드리자면,   
   <br>
   로그인 성공 -> `oauth2Login().successHandler`   
   로그인 실패 -> `oauth2Login().failureHandler`   
   회원정보 들어옴 -> `userInfoEndpoint().userService`      
   요청 특정 위치에 필터 -> `http.addFilterBefore`   
   와 같이 실행됩니다.   
   <br>
   

   그 인자들로 들어가는   
   ```java
   private final CustomOAuth2UserService customOAuth2UserService;
   private final JWTAuthenticationFilter jwtAuthenticationFilter;
   private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;
   private final CustomAuthenticationFailureHandler customAuthenticationFailureHandler;
   ```
   는 모두 만들어진 class 입니다.      
   <br>

   CustomOAuth2UserService 는    
   ![](img/implements%20OAuth2UserService.PNG)       
   의 구조로 들어가야 하기에   
   ```java
   CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User>
   ```
   다음과 같이 implements 합니다.   

   마찬가지로 모두 security 가 원하는 형식으로 맟춰줍니다.       
   ![](img/implements%20AuthenticationSuccessHandler.PNG)      
   ```java
   CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler
   ```
   ![](img/implements%20AuthenticationFailureHandler.PNG)   
   ```java
   CustomAuthenticationFailureHandler implements AuthenticationFailureHandler 
   ```
   <br>
   
   여기에서 jwt 필터를 설정하는 경우    
   ![](img/implements%20Filter.PNG)    
   다음과 같이 Filter 의 구조를 요구하는데   
   ```java
   JWTAuthenticationFilter extends OncePerRequestFilter
   ```
   저는 [OncePerRequestFilter](https://stackoverflow.com/questions/13152946/what-is-onceperrequestfilter) 를 사용하였습니다.   
   하나의 request 에 한번만 필터가 수행되게 규정하는 놈입니다.   
   JWT 의 유저가 실제 DB 상의 유저인지 확인하기 위해서는 쿼리가 실행되는데 
   이 쿼리가 최소한으로 실행되는 것이 좋다고 판단하여 채택하였습니다.   
   <br>

   그리고    
   ```java
   http.addFilterBefore(jwtAuthenticationFilter, BasicAuthenticationFilter.class);
   ```
   이 코드에서 addFilterBefore 는 security 에서 돌아가는 filter 사이에 어디에다가 넣을것이냐? 를 묻습니다.   
   그래서 해당 필터는 BasicAuthenticationFilter 이전에 실행됩니다.

   ![](img/securityFilterChain.PNG)   

   실제로 넣는 위치는 RememberMeAuthenticationFilter 이전에만 넣으신다면 어디든 상관 없습니다.   
   <br>

   필터 설명
   * SecurityContextPersistenceFilter - 요청(request)전에, SecurityContextRepository에서 받아온 정보를 SecurityContextHolder에 주입합니다.
   * LogoutFilter - 주체(Principal)의 로그아웃을 진행합니다. 주체는 보통 유저를 말합니다.
   * UsernamePasswordAuthenticationFilter - (로그인) 인증 과정을 진행합니다.
   * DefaultLoginPageGeneratingFilter - 사용자가 별도의 로그인 페이지를 구현하지 않은 경우, 스프링에서 기본적으로 설정한 로그인 페이지를 처리합니다.
   * BasicAuthenticationFilter - HTTP 요청의 (BASIC)인증 헤더를 처리하여 결과를 SecurityContextHolder에 저장합니다.
   * RememberMeAuthenticationFilter - SecurityContext에 인증(Authentication) 객체가 있는지 확인하고RememberMeServices를 구현한 객체의 요청이 있을 경우, Remember-Me(ex 사용자가 바로 로그인을 하기 위해서 저장 한 아이디와 패스워드)를 인증 토큰으로 컨텍스트에 주입합니다.
   * AnonymousAuthenticationFilter - SecurityContextHolder에 인증(Authentication) 객체가 있는지 확인하고, 필요한 경우 Authentication 객체를 주입합니다.
   * SessionManagementFilter - 요청이 시작된 이 후 인증된 사용자 인지 확인하고, 인증된 사용자일 경우SessionAuthenticationStrategy를 호출하여 세션 고정 보호 메커니즘을 활성화하거나 여러 동시 로그인을 확인하는 것과 같은 세션 관련 활동을 수행합니다.
   * ExceptionTranslationFilter - 필터 체인 내에서 발생(Throw)되는 모든 예외(AccessDeniedException, AuthenticationException)를 처리합니다.
   * FilterSecurityInterceptor - HTTP 리소스의 보안 처리를 수행합니다.   
   
   [출처 https://siyoon210.tistory.com/32](https://siyoon210.tistory.com/32)     
   <br>

   글을 유심히 읽어보시면   
   RememberMeAuthenticationFilter 이후부터 SecurityContext 의 Authentication 객체를 사용합니다.    
   그럼으로 Authentication 객체가 제대로 사용되기 위해서 그 이전에 jwt 에서 받아 객체를 저장해야 합니다.    
   </details>
   <br>