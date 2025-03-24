package com.cbcode.dealertasksV1.Cars.model;

import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;

@Entity
@Table(name = "cars")
@SequenceGenerator(name = "cars_seq", sequenceName = "cars_seq", initialValue =  1, allocationSize = 1)
public class Car implements Serializable {
	@Serial
	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "cars_seq")
	private Long id;
	@Column(nullable = false)
	private String brand;
	@Column(nullable = false)
	private String model;
	@Column(nullable = false)
	private String color;
	@Column(nullable = false, unique = true)
	private String chassisNumber;
	@Column(nullable = false, unique = true)
	private String registrationNumber;
	@Column(nullable = false)
	private Integer keysNumber;
	@Column(nullable = false)
	@JsonFormat(pattern = "dd-MM-yyyy", timezone = "Europe/London")
	@Temporal(TemporalType.DATE)
	private Date dateArrived;

	public Car() {
	}

	public Car(String brand, String model, String color, String chassisNumber, String registrationNumber,
	           Integer keysNumber, Date dateArrived) {
		this.brand = brand;
		this.model = model;
		this.color = color;
		this.chassisNumber = chassisNumber;
		this.registrationNumber = registrationNumber;
		this.keysNumber = keysNumber;
		this.dateArrived = dateArrived;
	}
}
