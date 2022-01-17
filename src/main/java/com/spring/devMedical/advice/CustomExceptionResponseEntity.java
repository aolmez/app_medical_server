package com.spring.devMedical.advice;

import java.util.Date;

import com.spring.devMedical.exception.PasswordNotConfirmedException;
import com.spring.devMedical.exception.ResourceNotFoundException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@RestControllerAdvice
public class CustomExceptionResponseEntity extends ResponseEntityExceptionHandler {

    @ExceptionHandler(Exception.class)
    public final ResponseEntity<ErrorMessage> handleAllException(Exception ex, WebRequest request) {
        return new ResponseEntity<ErrorMessage>(new ErrorMessage(HttpStatus.INTERNAL_SERVER_ERROR.value(), new Date(),
                ex.getMessage(), request.getDescription(false)), HttpStatus.INTERNAL_SERVER_ERROR);

    }

    @ExceptionHandler(ResourceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public final ResponseEntity<ErrorMessage> handleResourceNotFoundException(Exception ex, WebRequest request) {
        return new ResponseEntity<ErrorMessage>(new ErrorMessage(HttpStatus.NOT_FOUND.value(), new Date(),
                ex.getMessage(), request.getDescription(false)), HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(PasswordNotConfirmedException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public final ResponseEntity<ErrorMessage> handlePasswordNotConfirmedException(Exception ex, WebRequest request) {
        return new ResponseEntity<ErrorMessage>(new ErrorMessage(HttpStatus.BAD_REQUEST.value(), new Date(),
                ex.getMessage(), request.getDescription(false)), HttpStatus.BAD_REQUEST);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex,
            HttpHeaders headers, HttpStatus status, WebRequest request) {
        return new ResponseEntity<Object>(new ErrorMessage(HttpStatus.BAD_REQUEST.value(), new Date(), ex.getMessage(),
                request.getDescription(false)), HttpStatus.BAD_REQUEST);
    }

}