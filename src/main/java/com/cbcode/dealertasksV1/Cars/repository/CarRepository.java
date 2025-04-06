package com.cbcode.dealertasksV1.Cars.repository;

import com.cbcode.dealertasksV1.Cars.model.Car;
import com.cbcode.dealertasksV1.Cars.model.Enums.CarStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CarRepository extends JpaRepository<Car, Long> {
    @Query("SELECT c FROM Car c WHERE LOWER(c.registrationNumber) LIKE LOWER(CONCAT('%', :registrationNumber, '%'))")
    List<Car> findByRegistrationNumberContainingIgnoreCase(@Param("registrationNumber") String registrationNumber);

    @Query("SELECT c FROM Car c WHERE LOWER(c.chassisNumber) LIKE LOWER(CONCAT('%', :chassisNumber, '%'))")
    List<Car> findByChassisNumberContainingIgnoreCase(@Param("chassisNumber") String chassisNumber);

    @Query("SELECT c FROM Car c WHERE LOWER(c.model) LIKE LOWER(CONCAT('%', :model, '%'))")
    Page<Car> findByModelContainingIgnoreCase(@Param("model") String model, Pageable pageable);

    @Query("SELECT c FROM Car c WHERE LOWER(c.customerName) LIKE LOWER(CONCAT('%', :customerName, '%'))")
    List<Car> findByCustomerNameContainingIgnoreCase(@Param("customerName") String customerName);

    @Query("SELECT c FROM Car c WHERE c.status = :carStatus")
    Page<Car> findAllByCarStatus(@Param("carStatus") CarStatus carStatus, Pageable pageable);

    @Query("SELECT CASE WHEN COUNT(e) > 0 THEN true ELSE false END FROM Car e WHERE e.registrationNumber = :regNumber")
    boolean existsByRegNumber(@Param("regNumber") String regNumber);

    @Query("SELECT CASE WHEN COUNT(e) > 0 THEN true ELSE false END FROM Car e WHERE e.chassisNumber = :chassisNumber")
    boolean existsByChassisNumber(@Param("chassisNumber") String chassisNumber);

}
