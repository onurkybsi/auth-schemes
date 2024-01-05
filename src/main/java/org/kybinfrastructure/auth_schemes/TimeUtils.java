package org.kybinfrastructure.auth_schemes;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import org.springframework.stereotype.Component;

@Component
public class TimeUtils { // NOSONAR

  private final Clock clock;

  public TimeUtils(Clock clock) {
    this.clock = clock;
  }

  public TimeUtils() {
    this.clock = Clock.systemUTC();
  }

  public OffsetDateTime now() {
    return OffsetDateTime.now(clock);
  }

  public Instant instant() {
    return clock.instant();
  }

}
