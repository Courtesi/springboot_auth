package dev.wenslo.trueshotodds.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import dev.wenslo.trueshotodds.entity.User;
import dev.wenslo.trueshotodds.entity.UserRole;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

@JsonIgnoreProperties(ignoreUnknown = true)
public class CustomUserPrincipal implements UserDetails, Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @Getter
    private SessionUser sessionUser;
    private String password; // Store password separately for authentication

    public CustomUserPrincipal() {} // for Jackson

//    @JsonCreator
//    public CustomUserPrincipal(@JsonProperty("sessionUser") SessionUser, @JsonProperty("password") String) {
//        this.sessionUser = sessionUser;
//        this.password = password;
//    }

    public CustomUserPrincipal(SessionUser sessionUser, String password) {
        this.sessionUser = sessionUser;
        this.password = password;
    }

    public void setSessionUser(SessionUser sessionUser) { this.sessionUser = sessionUser; }

    public void setPassword(String password) { this.password = password; }

    @Override
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return mapRolesToAuthorities(sessionUser.getRoles());
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    @JsonIgnore
    public String getUsername() {
        return sessionUser.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        // For session-based checks, we assume account is not locked
        // Fresh database checks should be done in controllers if needed
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        // For session-based checks, we assume user is enabled
        // Fresh database checks should be done in controllers if needed
        return true;
    }

    @JsonIgnore
    public String getUserId() {
        return sessionUser.getUserId();
    }

    @JsonIgnore
    public String getEmail() {
        return sessionUser.getEmail();
    }

    @JsonIgnore
    public String getFullName() {
        return sessionUser.getFullName();
    }

    @JsonIgnore
    public Set<UserRole> getRoles() {
        return sessionUser.getRoles();
    }

    public static CustomUserPrincipal from(User user) {
        SessionUser sessionUser = SessionUser.from(user);
        // Use placeholder password for OAuth2 users to prevent null pointer exceptions
        String safePassword = user.getPassword() != null ? user.getPassword() : "{oauth2}";
        return new CustomUserPrincipal(sessionUser, safePassword);
    }

    private Collection<? extends GrantedAuthority> mapRolesToAuthorities(Set<UserRole> roles) {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                .collect(Collectors.toList());
    }
}