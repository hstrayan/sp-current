package com.pers.smartproxy.utils;

 class Dog {
	public void bark() {
		System.out.print("woof");
	}
	
}

class Hound extends Dog {
	public void sniff() {
		System.out.println("sniff");
	}
	public void bark() {
		System.out.println("howl");
	}
}

public class DogShow {
public static void main(String[] args) {
	new DogShow().go();
}
void go() {
	new Hound().bark();
	((Dog) new Hound()).bark();
	
}
}
