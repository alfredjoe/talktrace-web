import { calculateAnalytics } from './Analytics';

describe('calculateAnalytics Engine Unit Tests', () => {
  test('returns default metrics when segments are empty', () => {
    const data = calculateAnalytics([]);
    expect(data.totalSpeechSeconds).toBe(0);
    expect(data.speakerStats).toEqual([]);
    expect(data.silentGapsCount).toBe(0);
  });

  test('calculates duration, WPM, and percentage share accurately', () => {
    const mockSegments = [
      { start: 0, end: 10, speaker: 'Abin George', text: 'Hello everyone welcome to this Talktrace meeting class.' },
      { start: 15, end: 25, speaker: 'Sarah', text: 'Thank you Abin glad to join the session today.' }
    ];

    const data = calculateAnalytics(mockSegments);
    expect(data.totalSpeechSeconds).toBe(20);
    expect(data.silentGapsCount).toBe(1); // 5s gap > 2.5s
    expect(data.speakerStats.length).toBe(2);

    const abin = data.speakerStats.find(s => s.name === 'Abin George');
    const sarah = data.speakerStats.find(s => s.name === 'Sarah');

    expect(abin.durationSeconds).toBe(10);
    expect(abin.sharePercent).toBe(50);
    expect(sarah.durationSeconds).toBe(10);
    expect(sarah.sharePercent).toBe(50);
  });
});
