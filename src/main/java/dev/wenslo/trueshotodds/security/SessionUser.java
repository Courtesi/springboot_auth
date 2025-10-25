package dev.wenslo.trueshotodds.security;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import dev.wenslo.trueshotodds.entity.User;
import dev.wenslo.trueshotodds.entity.UserRole;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serial;
import java.io.Serializable;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

/**
 * Lightweight user representation for Redis session storage.
 * Contains only essential user information needed for authentication and authorization.
 */
@Data
@NoArgsConstructor
public class SessionUser implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private String userId;
    private String email;
    private String fullName;
//    @JsonDeserialize(as = HashSet.class)
    private Set<UserRole> roles;
    private LocalDateTime loginTime;

//    @JsonCreator
//    public SessionUser(@JsonProperty("userId") Long userId,
//                       @JsonProperty("email") String email,
//                       @JsonProperty("fullName") String fullName,
//                       @JsonProperty("roles") Set<UserRole> roles,
//                       @JsonProperty("loginTime") LocalDateTime loginTime) {
//        this.userId = userId;
//        this.email = email;
//        this.fullName = fullName;
//        this.roles = roles;
//        this.loginTime = loginTime;
//    }

    /**
     * Creates a SessionUser from a full User entity
     */
    public static SessionUser from(User user) {
        SessionUser sessionUser = new SessionUser();
        sessionUser.setUserId(user.getId());
        sessionUser.setEmail(user.getEmail());
        sessionUser.setFullName(user.getFullName());
        sessionUser.setRoles(new HashSet<>(user.getRoles()));
        sessionUser.setLoginTime(LocalDateTime.now());
        return sessionUser;
    }

    /**
     * Constructor for creating SessionUser from User entity
     */
    public SessionUser(User user) {
        this.userId = user.getId();
        this.email = user.getEmail();
        this.fullName = user.getFullName();
        this.roles = new HashSet<>(user.getRoles());
        this.loginTime = LocalDateTime.now();
    }
}