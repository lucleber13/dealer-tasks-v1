package com.cbcode.dealertasksV1.Cars.service.impl;

import com.cbcode.dealertasksV1.Cars.model.Car;
import com.cbcode.dealertasksV1.Cars.model.DTOs.CarDto;
import com.cbcode.dealertasksV1.Cars.model.DTOs.DisplayCarsDto;
import com.cbcode.dealertasksV1.Cars.repository.CarRepository;
import com.cbcode.dealertasksV1.Cars.service.CarService;
import com.cbcode.dealertasksV1.ExceptionsConfig.CarAlreadyExistsException;
import com.cbcode.dealertasksV1.ExceptionsConfig.CarMappingException;
import com.cbcode.dealertasksV1.Users.repository.UserRepository;
import jakarta.transaction.Transactional;
import org.jetbrains.annotations.NotNull;
import org.modelmapper.MappingException;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CarServiceImpl implements CarService {

    private static final Logger logger = LoggerFactory.getLogger(CarServiceImpl.class);

    private final CarRepository carRepository;
    private final ModelMapper modelMapper;
    private final UserRepository userRepository;

    public CarServiceImpl(CarRepository carRepository, ModelMapper modelMapper, UserRepository userRepository) {
        this.carRepository = carRepository;
        this.modelMapper = modelMapper;
        this.userRepository = userRepository;
    }

    /**
     * Creates a new car in the system with the provided details.
     * Ensures that the car's chassis number and registration number are unique.
     *
     * @param carDto an object containing the details of the car to be created, including its chassis number and registration number
     * @return the created car's details as a CarDto object
     * @throws CarAlreadyExistsException if a car with the same chassis number or registration number already exists
     */
    @Transactional
    @Override
    public CarDto createCar(@NotNull CarDto carDto) {
        logger.warn("Creating a new car with VIN: {} and number plate: {}", carDto.getChassisNumber(), carDto.getRegistrationNumber());

        var car = mapToCar(carDto);

        if (carRepository.existsByChassisNumber(car.getChassisNumber())) {
            logger.error("Car with chassis number {} already exists", car.getChassisNumber());
            throw new CarAlreadyExistsException("Car with VIN: " + carDto.getChassisNumber() + " already exists!");
        }

        if (carRepository.existsByRegNumber(car.getRegistrationNumber())) {
            logger.error("Car with registration number {} already exists", car.getRegistrationNumber());
            throw new CarAlreadyExistsException("Car with registration number: " + car.getRegistrationNumber() + " already exists!");
        }

        Car savedCar = carRepository.save(car);
        logger.info("Car with VIN: {} and number plate: {} successfully created", savedCar.getChassisNumber(), savedCar.getRegistrationNumber());

        return mapToCarDto(savedCar);
    }

    /**
     * Maps a CarDto object to a Car object.
     *
     * @param carDto the CarDto object to be mapped; must not be null
     * @return the mapped Car object
     * @throws IllegalArgumentException if the carDto parameter is null
     * @throws CarMappingException      if an error occurs during the mapping process
     */
    private Car mapToCar(final CarDto carDto) {
        if (carDto == null) {
            throw new IllegalArgumentException("Car DTO cannot be null");
        }
        try {
            return modelMapper.map(carDto, Car.class);
        } catch (MappingException e) {
            logger.error("Failed to map car DTO to car: {}", e.getMessage(), e);
            throw new CarMappingException("Failed to map car DTO to car", e);
        }
    }

    /**
     * Maps a given Car object to a CarDto object using the configured model mapper.
     *
     * @param car the Car object to be mapped; must not be null
     * @return the resulting CarDto object after mapping
     * @throws IllegalArgumentException if the provided car is null
     * @throws CarMappingException      if the mapping process fails
     */
    private CarDto mapToCarDto(final Car car) {
        if (car == null) {
            throw new IllegalArgumentException("Car cannot be null");
        }
        try {
            return modelMapper.map(car, CarDto.class);
        } catch (MappingException e) {
            logger.error("Failed to map car to DTO: {}", e.getMessage(), e);
            throw new CarMappingException("Failed to map car to DTO", e);
        }
    }

    /**
     * Retrieves a car by its unique identifier.
     *
     * @param id the unique identifier of the car to be retrieved
     * @return the CarDto object representing the retrieved car
     */
    @Override
    public CarDto getCarById(Long id) {
        logger.info("Getting car with ID: {}", id);
        var car = getCar(id);
        logger.info("Car with ID: {} successfully retrieved", id);
        return mapToCarDto(car);
    }

    /**
     * Retrieves a car by its unique identifier.
     * Throws an exception if the car is not found in the repository.
     *
     * @param id the unique identifier of the car to be retrieved
     * @return the car corresponding to the provided identifier
     * @throws IllegalArgumentException if no car with the given identifier is found
     */
    private Car getCar(Long id) {
        return carRepository.findById(id).orElseThrow(() -> {
            logger.error("Car with ID: {} not found", id);
            return new IllegalArgumentException("Car with ID: " + id + " not found");
        });
    }

    /**
     * @param id
     * @param carDto
     * @return
     */
    @Override
    public CarDto updateCarToSold(Long id, CarDto carDto) {
        return null;
    }

    /**
     * @param pageable
     * @return
     */
    @Override
    public Page<DisplayCarsDto> getAllCars(Pageable pageable) {
        return null;
    }

    /**
     * @param model
     * @param pageable
     * @return
     */
    @Override
    public Page<CarDto> getCarsByModel(String model, Pageable pageable) {
        return null;
    }

    /**
     * @param id
     */
    @Override
    public void deleteCarById(Long id) {

    }

    /**
     * @param regNumber
     * @return
     */
    @Override
    public List<CarDto> getCarByRegNumber(String regNumber) {
        return List.of();
    }

    /**
     * @param chassisNumber
     * @return
     */
    @Override
    public List<CarDto> getCarByChassisNumber(String chassisNumber) {
        return List.of();
    }

    /**
     * @param buyerName
     * @return
     */
    @Override
    public List<CarDto> getCarByBuyerName(String buyerName) {
        return List.of();
    }
}
