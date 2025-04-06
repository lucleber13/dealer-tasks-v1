package com.cbcode.dealertasksV1.Cars.model.DTOs;

import com.cbcode.dealertasksV1.Cars.model.Enums.CarStatus;
import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import org.springframework.format.annotation.DateTimeFormat;

import java.util.Date;
import java.util.Objects;

public class CarDto {
    private Long id;
    private String brand;
    private String model;
    private String color;
    private String chassisNumber;
    private String registrationNumber;
    private Integer keysNumber;
    @JsonFormat(pattern = "dd-MM-yyyy", shape = JsonFormat.Shape.STRING, timezone = "Europe/London")
    private Date dateArrived;
    @Enumerated(EnumType.STRING)
    private CarStatus status = CarStatus.IN_STOCK;
    private String customerName;
    @JsonFormat(pattern = "dd-MM-yyyy HH:mm", shape = JsonFormat.Shape.STRING, timezone = "Europe/London")
    @DateTimeFormat(pattern = "dd-MM-yyyy HH:mm")
    private Date dateHandover;

    public CarDto() {
    }

    public CarDto(Long id, String brand, String model, String color, String chassisNumber, String registrationNumber,
                  Integer keysNumber, Date dateArrived, CarStatus status, String customerName, Date dateHandover) {
        this.id = id;
        this.brand = brand;
        this.model = model;
        this.color = color;
        this.chassisNumber = chassisNumber;
        this.registrationNumber = registrationNumber;
        this.keysNumber = keysNumber;
        this.dateArrived = dateArrived;
        this.status = status;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getBrand() {
        return brand;
    }

    public void setBrand(String brand) {
        this.brand = brand;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public String getColor() {
        return color;
    }

    public void setColor(String color) {
        this.color = color;
    }

    public String getChassisNumber() {
        return chassisNumber;
    }

    public void setChassisNumber(String chassisNumber) {
        this.chassisNumber = chassisNumber;
    }

    public String getRegistrationNumber() {
        return registrationNumber;
    }

    public void setRegistrationNumber(String registrationNumber) {
        this.registrationNumber = registrationNumber;
    }

    public Integer getKeysNumber() {
        return keysNumber;
    }

    public void setKeysNumber(Integer keysNumber) {
        this.keysNumber = keysNumber;
    }

    public Date getDateArrived() {
        return dateArrived;
    }

    public void setDateArrived(Date dateArrived) {
        this.dateArrived = dateArrived;
    }

    public CarStatus getStatus() {
        return status;
    }

    public void setStatus(CarStatus status) {
        this.status = status;
    }

    public String getCustomerName() {
        return customerName;
    }

    public void setCustomerName(String customerName) {
        this.customerName = customerName;
    }

    public Date getDateHandover() {
        return dateHandover;
    }

    public void setDateHandover(Date dateHandover) {
        this.dateHandover = dateHandover;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof CarDto carDto)) return false;
        return Objects.equals(id, carDto.id)
                && Objects.equals(brand, carDto.brand)
                && Objects.equals(model, carDto.model)
                && Objects.equals(color, carDto.color)
                && Objects.equals(chassisNumber, carDto.chassisNumber)
                && Objects.equals(registrationNumber, carDto.registrationNumber)
                && Objects.equals(keysNumber, carDto.keysNumber)
                && Objects.equals(dateArrived, carDto.dateArrived)
                && status == carDto.status
                && Objects.equals(customerName, carDto.customerName)
                && Objects.equals(dateHandover, carDto.dateHandover);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, brand, model, color, chassisNumber, registrationNumber, keysNumber,
                dateArrived, status, customerName, dateHandover);
    }

    @Override
    public String toString() {
        return "CarDto{" +
                "id=" + id +
                ", brand='" + brand + '\'' +
                ", model='" + model + '\'' +
                ", color='" + color + '\'' +
                ", chassisNumber='" + chassisNumber + '\'' +
                ", registrationNumber='" + registrationNumber + '\'' +
                ", keysNumber=" + keysNumber +
                ", dateArrived=" + dateArrived +
                ", status=" + status +
                ", customerName='" + customerName + '\'' +
                ", dateHandover=" + dateHandover +
                '}';
    }
}
