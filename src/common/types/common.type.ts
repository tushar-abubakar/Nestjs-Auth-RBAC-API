export interface DurationBreakdown {
  days?: number;
  hours?: number;
  minutes?: number;
  seconds?: number;
}

export interface DurationResult {
  waitSeconds: number;
  breakdown: DurationBreakdown;
  waitFormatted: string;
}
