package com.cbcode.dealertasksV1.Cars.model;

import com.cbcode.dealertasksV1.Cars.model.Enums.CarStatus;
import com.fasterxml.jackson.annotation.JsonFormat;
import jakarta.persistence.*;
import org.springframework.format.annotation.DateTimeFormat;

import java.io.Serial;
import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

@Entity
@Table(name = "cars")
@SequenceGenerator(name = "cars_seq", sequenceName = "cars_seq", initialValue = 1, allocationSize = 1)
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
    @JsonFormat(pattern = "dd-MM-yyyy", shape = JsonFormat.Shape.STRING, timezone = "Europe/London")
    @Temporal(TemporalType.DATE)
    private Date dateArrived;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private CarStatus status = CarStatus.IN_STOCK;
    @Column(nullable = true)
    private String customerName;
    @Column(nullable = true)
    @JsonFormat(pattern = "dd-MM-yyyy HH:mm", shape = JsonFormat.Shape.STRING, timezone = "Europe/London")
    @DateTimeFormat(pattern = "dd-MM-yyyy HH:mm")
    @Temporal(TemporalType.DATE)
    private Date dateHandover;
    
    public Car() {
    }

    public Car(String brand, String model, String color, String chassisNumber, String registrationNumber,
               Integer keysNumber, Date dateArrived, CarStatus status, String customerName, Date dateHandover) {
        this.brand = brand;
        this.model = model;
        this.color = color;
        this.chassisNumber = chassisNumber;
        this.registrationNumber = registrationNumber;
        this.keysNumber = keysNumber;
        this.dateArrived = dateArrived;
        this.status = status;
        this.customerName = customerName;
        this.dateHandover = dateHandover;
    }

    public static class CarBuilder {
        private String brand;
        private String model;
        private String color;
        private String chassisNumber;
        private String registrationNumber;
        private Integer keysNumber;
        private Date dateArrived;
        private CarStatus status = CarStatus.IN_STOCK;
        private String customerName;
        private Date dateHandover;


        public CarBuilder brand(String brand) {
            this.brand = brand;
            return this;
        }

        public CarBuilder model(String model) {
            this.model = model;
            return this;
        }

        public CarBuilder color(String color) {
            this.color = color;
            return this;
        }

        public CarBuilder chassisNumber(String chassisNumber) {
            this.chassisNumber = chassisNumber;
            return this;
        }

        public CarBuilder registrationNumber(String registrationNumber) {
            this.registrationNumber = registrationNumber;
            return this;
        }

        public CarBuilder keysNumber(Integer keysNumber) {
            this.keysNumber = keysNumber;
            return this;
        }

        public CarBuilder dateArrived(Date dateArrived) {
            this.dateArrived = dateArrived;
            return this;
        }

        public CarBuilder status(CarStatus status) {
            this.status = status;
            return this;
        }

        public CarBuilder customerName(String customerName) {
            this.customerName = customerName;
            return this;
        }

        public CarBuilder dateHandover(Date dateHandover) {
            this.dateHandover = dateHandover;
            return this;
        }

        public static CarBuilder stockCar(String brand, String model, String color, String chassisNumber, String registrationNumber,
                                          Integer keysNumber, Date dateArrived) {
            return new CarBuilder()
                    .brand(brand)
                    .model(model)
                    .color(color)
                    .chassisNumber(chassisNumber)
                    .registrationNumber(registrationNumber)
                    .keysNumber(keysNumber)
                    .dateArrived(dateArrived)
                    .status(CarStatus.IN_STOCK);
        }

        public static CarBuilder soldCar(String brand, String model, String color, String chassisNumber, String registrationNumber,
                                         Integer keysNumber, Date dateArrived, String customerName, Date dateHandover) {
            return new CarBuilder()
                    .brand(brand)
                    .model(model)
                    .color(color)
                    .chassisNumber(chassisNumber)
                    .registrationNumber(registrationNumber)
                    .keysNumber(keysNumber)
                    .dateArrived(dateArrived)
                    .status(CarStatus.SOLD)
                    .customerName(customerName)
                    .dateHandover(dateHandover);
        }

        public Car carBuild() {
            return new Car(brand, model, color, chassisNumber, registrationNumber, keysNumber, dateArrived, status, customerName, dateHandover);
        }
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
        if (!(o instanceof Car car)) return false;
        return Objects.equals(id, car.id)
                && Objects.equals(brand, car.brand)
                && Objects.equals(model, car.model)
                && Objects.equals(color, car.color)
                && Objects.equals(chassisNumber, car.chassisNumber)
                && Objects.equals(registrationNumber, car.registrationNumber)
                && Objects.equals(keysNumber, car.keysNumber)
                && Objects.equals(dateArrived, car.dateArrived)
                && Objects.equals(status, car.status)
                && Objects.equals(customerName, car.customerName)
                && Objects.equals(dateHandover, car.dateHandover);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, brand, model, color, chassisNumber, registrationNumber, keysNumber,
                dateArrived, status, customerName, dateHandover);
    }
}
