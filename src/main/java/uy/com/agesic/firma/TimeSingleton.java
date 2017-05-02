package uy.com.agesic.firma;

public class TimeSingleton {

	private static TimeSingleton instance = null;

	protected TimeSingleton() {
		// Exists only to defeat instantiation.
	}

	public static TimeSingleton getInstance() {
		if (instance == null) {
			instance = new TimeSingleton();
		}
		return instance;
	}

	private Long[] currentTime = new Long[2];

	public Long[] getCurrentTime() {
		return currentTime;
	}

	public void setFirstTime() {
		this.currentTime[0] = System.currentTimeMillis();
	}

	public void setSecondTime() {
		this.currentTime[1] = System.currentTimeMillis();
	}

}
