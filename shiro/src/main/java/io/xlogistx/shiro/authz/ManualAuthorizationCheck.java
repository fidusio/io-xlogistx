package io.xlogistx.shiro.authz;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE_PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;


@Retention(RUNTIME)
@Target({ METHOD, TYPE_PARAMETER })
public @interface ManualAuthorizationCheck {

}
