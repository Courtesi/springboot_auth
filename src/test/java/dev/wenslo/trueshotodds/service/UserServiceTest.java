package dev.wenslo.trueshotodds.service;

import dev.wenslo.trueshotodds.dto.request.RegisterRequest;
import dev.wenslo.trueshotodds.dto.response.ProfileResponse;
import dev.wenslo.trueshotodds.entity.*;
import dev.wenslo.trueshotodds.exception.UserAlreadyExistsException;
import dev.wenslo.trueshotodds.repository.SubscriptionRepository;
import dev.wenslo.trueshotodds.repository.UserPreferencesRepository;
import dev.wenslo.trueshotodds.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private SubscriptionRepository subscriptionRepository;

    @Mock
    private UserPreferencesRepository preferencesRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private EmailService emailService;

    @InjectMocks
    private UserService userService;

    private RegisterRequest registerRequest;
    private User testUser;
    private Subscription testSubscription;
    private UserPreferences testPreferences;

    @BeforeEach
    void setUp() {
        registerRequest = new RegisterRequest();
        registerRequest.setEmail("test@example.com");
        registerRequest.setFullName("Test User");
        registerRequest.setPassword("password123");
        registerRequest.setConfirmPassword("password123");

        testUser = new User();
        testUser.setId("wow");
        testUser.setEmail("test@example.com");
        testUser.setFullName("Test User");
        testUser.setPassword("encodedPassword");
        testUser.setRoles(Set.of(UserRole.USER));
        testUser.setStatus(UserStatus.ACTIVE);
        testUser.setCreatedAt(LocalDateTime.now());
        testUser.setEmailVerified(true);

        testSubscription = new Subscription();
        testSubscription.setId(1L);
        testSubscription.setUser(testUser);
        testSubscription.setPlan(SubscriptionPlan.FREE);
        testSubscription.setStatus(SubscriptionStatus.ACTIVE);

        testPreferences = new UserPreferences();
        testPreferences.setId(1L);
        testPreferences.setUser(testUser);
        testPreferences.setNotifications(true);
        testPreferences.setEmailUpdates(true);
    }

    @Test
    void registerUser_Success() {
        when(userRepository.existsByEmailIgnoreCase(anyString())).thenReturn(false);
        when(passwordEncoder.encode(anyString())).thenReturn("encodedPassword");
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(subscriptionRepository.save(any(Subscription.class))).thenReturn(testSubscription);
        when(preferencesRepository.save(any(UserPreferences.class))).thenReturn(testPreferences);

        User result = userService.registerUser(registerRequest);

        assertNotNull(result);
        assertEquals(testUser.getEmail(), result.getEmail());
        verify(userRepository).existsByEmailIgnoreCase("test@example.com");
        verify(userRepository).save(any(User.class));
        verify(subscriptionRepository).save(any(Subscription.class));
        verify(preferencesRepository).save(any(UserPreferences.class));
        verify(emailService).sendEmailVerification(anyString(), anyString(), anyString());
    }

    @Test
    void registerUser_UserAlreadyExists() {
        when(userRepository.existsByEmailIgnoreCase(anyString())).thenReturn(true);

        assertThrows(UserAlreadyExistsException.class, () -> {
            userService.registerUser(registerRequest);
        });

        verify(userRepository, never()).save(any(User.class));
        verify(emailService, never()).sendEmailVerification(anyString(), anyString(), anyString());
    }

    @Test
    void getUserProfile_Success() {
        when(userRepository.findById("wow")).thenReturn(Optional.of(testUser));
        when(subscriptionRepository.findByUserId("wow")).thenReturn(Optional.of(testSubscription));
        when(preferencesRepository.findByUserId("wow")).thenReturn(Optional.of(testPreferences));

        ProfileResponse result = userService.getUserProfile("wow");

        assertNotNull(result);
        assertEquals("test@example.com", result.getEmail());
        assertEquals("Test User", result.getFullName());
        assertNotNull(result.getSubscription());
        assertEquals("free", result.getSubscription().getPlan());
        assertNotNull(result.getPreferences());
        assertTrue(result.getPreferences().getNotifications());
    }

    @Test
    void handleFailedLoginAttempt() {
        when(userRepository.findByEmailIgnoreCase("test@example.com")).thenReturn(Optional.of(testUser));

        userService.handleFailedLoginAttempt("test@example.com");

        verify(userRepository).incrementFailedLoginAttempts("test@example.com");
    }

    @Test
    void verifyEmail_Success() {
        testUser.setEmailVerificationToken("valid-token");
        testUser.setEmailVerificationTokenExpiresAt(LocalDateTime.now().plusHours(1));
        testUser.setStatus(UserStatus.PENDING_VERIFICATION);

        when(userRepository.findByEmailVerificationToken("valid-token")).thenReturn(Optional.of(testUser));

        assertDoesNotThrow(() -> userService.verifyEmail("valid-token"));

        verify(userRepository).verifyUserEmail("valid-token", UserStatus.ACTIVE);
    }

    @Test
    void verifyEmail_ExpiredToken() {
        testUser.setEmailVerificationToken("expired-token");
        testUser.setEmailVerificationTokenExpiresAt(LocalDateTime.now().minusHours(1));

        when(userRepository.findByEmailVerificationToken("expired-token")).thenReturn(Optional.of(testUser));

        assertThrows(IllegalArgumentException.class, () -> {
            userService.verifyEmail("expired-token");
        });
    }
}