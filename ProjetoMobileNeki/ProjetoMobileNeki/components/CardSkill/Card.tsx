import { View, Text, StyleSheet, TouchableOpacity } from 'react-native';
import React from 'react';
import { CardSkillProps, SkillType } from '../../interfaces/TypesSkill';
import { FontAwesomeIcon } from '@fortawesome/react-native-fontawesome';
import { faEdit, faTrash } from '@fortawesome/free-solid-svg-icons';

export default function CardSkill({ skill, handleAtualizar, handleDeletar }: CardSkillProps) {
  return (
    <View style={styles.container}>
      <Text style={styles.skillName}>{skill.nome}</Text>
      <View style={styles.buttonContainer}>
        <TouchableOpacity style={styles.button} onPress={() => handleAtualizar(skill.id, skill.nivel)}>
          <FontAwesomeIcon icon={faEdit} size={20} color="#fff" />
        </TouchableOpacity>
        <TouchableOpacity style={styles.button} onPress={() => handleDeletar(skill.id)}>
          <FontAwesomeIcon icon={faTrash} size={20} color="#fff" />
        </TouchableOpacity>
      </View>
    </View>
  );
}
const styles = StyleSheet.create({
  container: {
    backgroundColor: '#ffffff', 
    borderRadius: 8,
    borderWidth: 2,
    borderColor: '#8e44ad',
    padding: 16,
    marginVertical: 8,
    marginHorizontal: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  skillName: {
    fontSize: 18,
    color: '#333',
    marginBottom: 12,
  },
  buttonContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
  },
  button: {
    backgroundColor: '#8e44ad', 
    padding: 8,
    borderRadius: 6,
    marginHorizontal: 4,
  },
});
